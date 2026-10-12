// Copyright 1998-2017 Epic Games, Inc. All Rights Reserved.

/*=============================================================================================
	GXMGpuProfiler.cpp: per-scene GPU timing for Development builds, recorded to ux0:data.

	WHAT IT MEASURES. libgxm has no GPU timer query, and Razor's own GPU tooling needs DevKit modules a retail
	unit does not have. What this RHI does have is the frame fence: every sceGxmEndScene() carries a
	notification the GPU writes when that scene's fragment processing completes (see GXMEnsureFrameFence). A
	watcher thread sleeps in sceGxmWaitEvent() - which <gxm/init.h> says may be called from any thread, and which
	wakes on every GPU job completion - and timestamps each fence value as it appears. With the CPU-side times
	of each scene's open, sceGxmEndScene() call and return, that gives per scene:

	  gpu   = done - max(submit, previous scene's done)    the GPU time this scene accounts for, since
	                                                       scenes complete in submission order
	  queue = max(0, previous scene's done - submit)       how long it waited behind earlier scenes

	Vertex processing can start before sceGxmEndScene() - the VDM ring kicks jobs mid-scene - so gpu is the
	scene's fragment processing plus whatever of its vertex work was still running at submit. Ranking scenes
	by it is sound; summing it over a frame gives the GPU's busy time for that frame.

	r.PSP2.GpuProfile 2 replaces the watcher with sceGxmFinish() after every scene, so each scene is timed with
	nothing else on the GPU: exact per-scene cost, at a lower frame rate.

	WHAT A SCENE IS CALLED. The draw event stack (SCOPED_DRAW_EVENT, arriving as RHIPushEvent/RHIPopEvent) at
	the moment the scene opened, plus the draws and indices issued under each innermost event inside it.
	GEmitDrawEvents is forced on while recording and restored afterwards.

	WHEN IT RECORDS.
	  - -GpuProfile=<frames> on the command line (ux0:app/<title id>/ue4commandline.txt on the device), starting
	    -GpuProfileDelay=<seconds> after the RHI comes up (default 30). -GpuProfileSerial selects mode 2.
	  - r.PSP2.GpuProfile set to 1 or 2, until it goes back to 0 or r.PSP2.GpuProfile.Frames frames have passed.
	  - L + R + SELECT held for a second: GXMProf_ComboFrames frames. Holding it again stops early.
	  - While ux0:data/rrc_capturing exists. retail_razorconnect creates that file when Razor starts a capture
	    and deletes it at Stop, so a Razor capture of the game produces this recording as well, and the plugin
	    merges it into the trace.

	OUTPUT. ux0:data/gxm_gpu_<unix time>.csv, written by its own thread so the render thread never waits on
	the memory card. The file starts with a header naming every column. The slowest scenes of the recording
	are also summarised to LogGXM when it ends, which reaches Console Output.

	Timestamps are sceKernelGetProcessTimeWide() microseconds (FPlatformTime::Cycles64).
==============================================================================================*/

#include "GXMRHIPrivate.h"

#if GXM_GPU_PROFILER

#include "HAL/Runnable.h"
#include "HAL/RunnableThread.h"
#include "Misc/ScopeLock.h"
#include "Misc/DateTime.h"
#include "Misc/Parse.h"
#include "Misc/CommandLine.h"

// GGameThreadTime and GRenderThreadTime for the frame lines.
#include "RenderCore.h"

#include <kernel/threadmgr.h>
#include <kernel/iofilemgr.h>
#include <ctrl.h>

DECLARE_LOG_CATEGORY_EXTERN(LogGXMGpuProfile, Log, All);
DEFINE_LOG_CATEGORY(LogGXMGpuProfile);

// Names carry a GXMProf_ / GProf / Prof prefix rather than living in a namespace: this module builds as one
// unity translation unit, where a file-scope using-directive would leak into the files after this one.
enum : int32
{
		GXMProf_MaxEventDepth		= 24,
		GXMProf_MaxEventName		= 40,
		GXMProf_MaxPathChars		= 160,
		GXMProf_MaxSections			= 8,
		GXMProf_MaxPendingScenes	= 64,

		/** Power of two. Must exceed the scenes that can complete between two frame ends by a wide margin. */
		GXMProf_CompletionSlots		= 256,

		/** Text waiting for the writer thread. Past this, whole lines are dropped and counted. */
		GXMProf_MaxBufferedBytes	= 256 * 1024,

		GXMProf_MaxSummaryKeys		= 48,

		/** Frames a pad-combo recording lasts: twenty seconds at 30 FPS. */
		GXMProf_ComboFrames			= 600,

		/** Frames to keep collecting completions after a recording stops, before the file is closed. */
		GXMProf_DrainFrames			= 15,

		/**
		 * The longest a recording started by the Razor flag file may run: five minutes at 30 FPS, about 20 MiB of
		 * CSV. If retail_razorconnect dies mid-capture the flag outlives it, and without this the game would write
		 * to the memory card until it filled. Once hit, the flag has to disappear before it can start another.
		 */
		GXMProf_RazorMaxFrames		= 9000,
};

/** Marks a control line in the text stream: the writer opens or closes the file when it reaches one. */
static const ANSICHAR GXMProf_ControlByte = '\x01';

static const char* const GXMProf_RazorFlagPath = "ux0:data/rrc_capturing";

static TAutoConsoleVariable<int32> CVarPSP2GpuProfile(
	TEXT("r.PSP2.GpuProfile"),
	0,
	TEXT("Records per-scene GPU timing to ux0:data/gxm_gpu_<time>.csv (non-Shipping builds only).\n")
	TEXT(" 0: only while a Razor capture is running or after L+R+SELECT is held for a second\n")
	TEXT(" 1: record; scenes are timed from their frame fence, so pacing is unchanged\n")
	TEXT(" 2: record with sceGxmFinish() after every scene; exact per-scene cost, lower frame rate"),
	ECVF_RenderThreadSafe);

static TAutoConsoleVariable<int32> CVarPSP2GpuProfileFrames(
	TEXT("r.PSP2.GpuProfile.Frames"),
	0,
	TEXT("Stops a recording started by r.PSP2.GpuProfile after this many frames. 0: no limit.\n")
	TEXT("Set r.PSP2.GpuProfile to 0 and back to start another."),
	ECVF_RenderThreadSafe);

/*-----------------------------------------------------------------------------
	Records. Render thread only, except where marked.
-----------------------------------------------------------------------------*/

struct FGXMProfSection
{
	ANSICHAR	Name[GXMProf_MaxEventName];
	uint32		Draws;
	uint64		Indices;
};

struct FGXMProfScene
{
	uint64		Frame;
	uint64		OpenUs;
	uint64		EndCallUs;
	uint64		SubmitUs;
	uint64		DoneUs;
	uint64		SerialUs;
	uint64		Indices;
	uint32		Fence;
	uint32		Width;
	uint32		Height;
	uint32		Draws;
	int32		NumSections;
	ANSICHAR	Kind;
	bool		bEnded;
	ANSICHAR	Path[GXMProf_MaxPathChars];
	FGXMProfSection Sections[GXMProf_MaxSections];
};

struct FGXMProfSummary
{
	ANSICHAR	Kind;
	uint32		Width;
	uint32		Height;
	ANSICHAR	Path[GXMProf_MaxPathChars];
	uint32		Count;
	uint64		GpuUs;
	uint64		MaxGpuUs;
	uint64		Draws;
	uint64		Indices;
};

enum class EGXMProfSource : uint8
{
	None,
	CommandLine,
	CVar,
	Combo,
	Razor,
};

static ANSICHAR			GProfEventNames[GXMProf_MaxEventDepth][GXMProf_MaxEventName];
static int32			GProfEventDepth = 0;

static FGXMProfScene	GProfPending[GXMProf_MaxPendingScenes];
static int32			GProfPendingHead = 0;
static int32			GProfPendingCount = 0;
static FGXMProfScene*	GProfOpenScene = nullptr;
static int32			GProfOpenSection = -1;

static FGXMProfSummary	GProfSummary[GXMProf_MaxSummaryKeys];
static int32			GProfNumSummary = 0;

/** 0 idle, 1 fence-timed, 2 serial. Non-zero while recording or draining. */
static int32			GProfMode = 0;
static bool				GProfRecording = false;
static int32			GProfDrainFramesLeft = 0;
static EGXMProfSource	GProfSource = EGXMProfSource::None;
static int32			GProfLastCVarMode = 0;
static uint64			GProfFrameLimit = 0;
static bool				GProfSavedEmitDrawEvents = false;
static bool				GProfRazorLatched = false;

/** -GpuProfile=<frames>: armed at startup, fired once when the delay has passed. */
static uint64			GProfCmdLineFrames = 0;
static uint64			GProfCmdLineAtUs = 0;
static int32			GProfCmdLineMode = 1;

static uint64			GProfRecordingStartUs = 0;
static uint64			GProfFrameStartUs = 0;
static uint64			GProfFramesRecorded = 0;
static uint64			GProfFrameSumUs = 0;
static uint64			GProfGpuSumUs = 0;
static uint64			GProfLastDoneUs = 0;
static uint32			GProfScenesThisFrame = 0;
static uint32			GProfDroppedScenes = 0;
static uint32			GProfUnknownDone = 0;
static uint64			GProfFrameWaitUs[(int32)EGXMGpuProfWait::Num] = { 0 };

/** Written by the watcher thread. A 32-bit aligned write is atomic on this CPU. */
static uint64			GProfCompletionUs[GXMProf_CompletionSlots];
static volatile uint32	GProfWatcherLastFence = 0;
static volatile uint32	GProfWatcherPrimeFence = 0;
static volatile int32	GProfWatcherPrimed = 0;
static volatile int32	GProfWatcherWanted = 0;

/** Written by the writer thread's input polling. */
static volatile int32	GProfRazorCapturing = 0;
static volatile int32	GProfComboPressed = 0;

static volatile int32	GProfStopThreads = 0;

/** Lines for the writer thread, and the count of bytes it had to drop. */
static FCriticalSection	GProfTextLock;
static TArray<ANSICHAR>	GProfText;
static uint32			GProfDroppedBytes = 0;

/*-----------------------------------------------------------------------------
	Text output.
-----------------------------------------------------------------------------*/

static void ProfAppendText(const ANSICHAR* Data, int32 Length)
{
	if (Length <= 0)
	{
		return;
	}

	FScopeLock Guard(&GProfTextLock);

	if (GProfText.Num() + Length > GXMProf_MaxBufferedBytes && Data[0] != GXMProf_ControlByte)
	{
		GProfDroppedBytes += (uint32)Length;
		return;
	}

	GProfText.Append(Data, Length);
}

static void ProfAppendLine(const ANSICHAR* Format, ...)
{
	ANSICHAR Line[1536];

	va_list Args;
	va_start(Args, Format);
	int32 Length = FCStringAnsi::GetVarArgs(Line, (SIZE_T)(sizeof(Line) - 1), (int32)(sizeof(Line) - 1), Format, Args);
	va_end(Args);

	if (Length < 0 || Length > (int32)sizeof(Line) - 2)
	{
		Length = (int32)sizeof(Line) - 2;
	}

	Line[Length++] = '\n';
	ProfAppendText(Line, Length);
}

/** Copies a name for a CSV field: no separators, no spaces, no control characters. */
static void ProfCopySanitised(ANSICHAR* Dest, int32 DestSize, const ANSICHAR* Source)
{
	int32 Out = 0;
	for (; Source != nullptr && *Source != 0 && Out < DestSize - 1; ++Source)
	{
		ANSICHAR Char = *Source;
		if (Char <= ' ' || Char == ',' || Char == '|' || Char == '=' || Char == '/' || Char == '"' || (uint8)Char >= 0x7f)
		{
			Char = '_';
		}
		Dest[Out++] = Char;
	}
	Dest[Out] = 0;
}

/*-----------------------------------------------------------------------------
	Writer thread: owns the file and polls the triggers that are not console variables.
-----------------------------------------------------------------------------*/

class FGXMProfWriter : public FRunnable
{
public:
	virtual uint32 Run() override
	{
		TArray<ANSICHAR> Local;
		SceUID File = -1;
		int32 ComboHeldPolls = 0;
		uint32 Poll = 0;

		while (GProfStopThreads == 0)
		{
			// Every 100 ms: the Razor capture flag and the pad combo.
			if ((Poll++ % 2) == 0)
			{
				SceIoStat Stat;
				FPlatformAtomics::InterlockedExchange(&GProfRazorCapturing, (sceIoGetstat(GXMProf_RazorFlagPath, &Stat) >= 0) ? 1 : 0);

				SceCtrlData Pad;
				FMemory::Memzero(Pad);
				const uint32 Combo = SCE_CTRL_L | SCE_CTRL_R | SCE_CTRL_SELECT;
				if (sceCtrlPeekBufferPositive(0, &Pad, 1) >= 0 && (Pad.buttons & Combo) == Combo)
				{
					// Fires once per hold, a second in.
					if (++ComboHeldPolls == 10)
					{
						FPlatformAtomics::InterlockedExchange(&GProfComboPressed, 1);
					}
				}
				else
				{
					ComboHeldPolls = 0;
				}
			}

			{
				FScopeLock Guard(&GProfTextLock);
				Exchange(Local, GProfText);
				GProfText.Reset();
			}

			// Walk the text, acting on control lines in order so a file never receives another file's lines.
			int32 Start = 0;
			while (Start < Local.Num())
			{
				if (Local[Start] == GXMProf_ControlByte)
				{
					int32 End = Start;
					while (End < Local.Num() && Local[End] != '\n')
					{
						++End;
					}

					ANSICHAR Control[256];
					const int32 ControlLength = FMath::Min(End - Start - 1, (int32)sizeof(Control) - 1);
					FMemory::Memcpy(Control, &Local[Start + 1], FMath::Max(ControlLength, 0));
					Control[FMath::Max(ControlLength, 0)] = 0;

					if (FCStringAnsi::Strncmp(Control, "OPEN ", 5) == 0)
					{
						if (File >= 0)
						{
							sceIoClose(File);
						}
						File = sceIoOpen(Control + 5, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);
						if (File < 0)
						{
							UE_LOG(LogGXMGpuProfile, Warning, TEXT("Could not create %s (0x%08x); this recording goes to the log summary only."), ANSI_TO_TCHAR(Control + 5), (uint32)File);
						}
					}
					else if (FCStringAnsi::Strncmp(Control, "CLOSE", 5) == 0 && File >= 0)
					{
						sceIoClose(File);
						File = -1;
					}

					Start = End + 1;
					continue;
				}

				int32 End = Start;
				while (End < Local.Num() && Local[End] != GXMProf_ControlByte)
				{
					++End;
				}

				if (File >= 0)
				{
					sceIoWrite(File, &Local[Start], (SceSize)(End - Start));
				}
				Start = End;
			}
			Local.Reset();

			sceKernelDelayThread(50 * 1000);
		}

		if (File >= 0)
		{
			sceIoClose(File);
		}
		return 0;
	}
};

/*-----------------------------------------------------------------------------
	Watcher thread: timestamps each frame fence value as the GPU writes it.
-----------------------------------------------------------------------------*/

class FGXMProfWatcher : public FRunnable
{
public:
	virtual uint32 Run() override
	{
		bool bPrimed = false;

		while (GProfStopThreads == 0)
		{
			if (GProfWatcherWanted == 0)
			{
				if (bPrimed)
				{
					bPrimed = false;
					FPlatformAtomics::InterlockedExchange(&GProfWatcherPrimed, 0);
				}
				sceKernelDelayThread(20 * 1000);
				continue;
			}

			if (bPrimed)
			{
				// Returns on any GPU job completion for any process, or a driver timeout. Not a wedge risk for
				// the render thread: only this thread ever waits here.
				if (sceGxmWaitEvent() < 0)
				{
					sceKernelDelayThread(1000);
				}
			}

			const uint32 Completed = GXMGetCompletedFenceValue();
			const uint64 Now = FPlatformTime::Cycles64();

			if (!bPrimed)
			{
				// Anything at or before this value completed at an unknown time; the render thread reports it so.
				FMemory::Memzero(GProfCompletionUs, sizeof(GProfCompletionUs));
				GProfWatcherLastFence = Completed;
				GProfWatcherPrimeFence = Completed;
				FPlatformAtomics::InterlockedExchange(&GProfWatcherPrimed, 1);
				bPrimed = true;
				continue;
			}

			if (Completed != GProfWatcherLastFence)
			{
				// Several scenes can finish between two wake-ups; they share this timestamp, and the render
				// thread charges the whole interval to the first of them.
				uint32 Steps = Completed - GProfWatcherLastFence;
				if (Steps > (uint32)GXMProf_CompletionSlots)
				{
					Steps = (uint32)GXMProf_CompletionSlots;
				}
				for (uint32 Step = 0; Step < Steps; ++Step)
				{
					GProfCompletionUs[(Completed - Step) & (GXMProf_CompletionSlots - 1)] = Now;
				}
				GProfWatcherLastFence = Completed;
			}
		}
		return 0;
	}
};

static FGXMProfWriter		GProfWriter;
static FGXMProfWatcher		GProfWatcher;
static FRunnableThread*		GProfWriterThread = nullptr;
static FRunnableThread*		GProfWatcherThread = nullptr;

/*-----------------------------------------------------------------------------
	Scene bookkeeping.
-----------------------------------------------------------------------------*/

static const ANSICHAR* ProfInnermostEventName()
{
	if (GProfEventDepth <= 0)
	{
		return "(none)";
	}
	return GProfEventNames[FMath::Min(GProfEventDepth, (int32)GXMProf_MaxEventDepth) - 1];
}

static int32 ProfFindOrAddSection(FGXMProfScene& Scene, const ANSICHAR* Name)
{
	for (int32 Index = 0; Index < Scene.NumSections; ++Index)
	{
		if (FCStringAnsi::Strcmp(Scene.Sections[Index].Name, Name) == 0)
		{
			return Index;
		}
	}

	if (Scene.NumSections < GXMProf_MaxSections)
	{
		FGXMProfSection& Section = Scene.Sections[Scene.NumSections];
		FCStringAnsi::Strncpy(Section.Name, Name, GXMProf_MaxEventName);
		Section.Draws = 0;
		Section.Indices = 0;
		return Scene.NumSections++;
	}

	// Past the table, draws go to the last slot, which is renamed to say so.
	FCStringAnsi::Strncpy(Scene.Sections[GXMProf_MaxSections - 1].Name, "(more)", GXMProf_MaxEventName);
	return GXMProf_MaxSections - 1;
}

static bool ProfIsFenceReached(uint32 Written, uint32 Wanted)
{
	return (int32)(Written - Wanted) >= 0;
}

static void ProfAddToSummary(const FGXMProfScene& Scene, uint64 GpuUs)
{
	FGXMProfSummary* Entry = nullptr;
	for (int32 Index = 0; Index < GProfNumSummary; ++Index)
	{
		FGXMProfSummary& Candidate = GProfSummary[Index];
		if (Candidate.Kind == Scene.Kind && Candidate.Width == Scene.Width && Candidate.Height == Scene.Height && FCStringAnsi::Strcmp(Candidate.Path, Scene.Path) == 0)
		{
			Entry = &Candidate;
			break;
		}
	}

	if (Entry == nullptr)
	{
		if (GProfNumSummary == GXMProf_MaxSummaryKeys)
		{
			return;
		}
		Entry = &GProfSummary[GProfNumSummary++];
		FMemory::Memzero(*Entry);
		Entry->Kind = Scene.Kind;
		Entry->Width = Scene.Width;
		Entry->Height = Scene.Height;
		FCStringAnsi::Strncpy(Entry->Path, Scene.Path, GXMProf_MaxPathChars);
	}

	++Entry->Count;
	Entry->GpuUs += GpuUs;
	Entry->MaxGpuUs = FMath::Max(Entry->MaxGpuUs, GpuUs);
	Entry->Draws += Scene.Draws;
	Entry->Indices += Scene.Indices;
}

static void ProfEmitScene(FGXMProfScene& Scene)
{
	uint64 GpuUs = 0;
	uint64 QueueUs = 0;

	if (Scene.DoneUs != 0)
	{
		const uint64 GpuStart = FMath::Max(Scene.SubmitUs, GProfLastDoneUs);
		GpuUs = (Scene.DoneUs > GpuStart) ? (Scene.DoneUs - GpuStart) : 0;
		QueueUs = (GProfLastDoneUs > Scene.SubmitUs) ? (GProfLastDoneUs - Scene.SubmitUs) : 0;
		GProfLastDoneUs = FMath::Max(GProfLastDoneUs, Scene.DoneUs);
		GProfGpuSumUs += GpuUs;
		ProfAddToSummary(Scene, GpuUs);
	}
	else
	{
		++GProfUnknownDone;
	}

	ANSICHAR Sections[GXMProf_MaxSections * (GXMProf_MaxEventName + 24)];
	int32 Used = 0;
	Sections[0] = 0;
	for (int32 Index = 0; Index < Scene.NumSections && Used < (int32)sizeof(Sections) - 1; ++Index)
	{
		const FGXMProfSection& Section = Scene.Sections[Index];
		const int32 Written = FCStringAnsi::Snprintf(Sections + Used, (int32)sizeof(Sections) - Used, "%s%s=%u/%llu",
			(Index > 0) ? "|" : "", Section.Name, Section.Draws, (unsigned long long)Section.Indices);
		if (Written <= 0)
		{
			break;
		}
		Used = FMath::Min(Used + Written, (int32)sizeof(Sections) - 1);
	}

	ProfAppendLine("S,%llu,%u,%c,%u,%u,%u,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%s,%s",
		(unsigned long long)Scene.Frame, Scene.Fence, Scene.Kind, Scene.Width, Scene.Height, Scene.Draws,
		(unsigned long long)Scene.Indices,
		(unsigned long long)Scene.OpenUs, (unsigned long long)Scene.EndCallUs, (unsigned long long)Scene.SubmitUs,
		(unsigned long long)Scene.DoneUs, (unsigned long long)GpuUs, (unsigned long long)QueueUs,
		(unsigned long long)Scene.SerialUs,
		Scene.Path, Sections);
}

/** Emits every finished scene whose completion is known, oldest first. With bFlush, unknown ones go out too. */
static void ProfDrainPendingScenes(bool bFlush)
{
	const bool bPrimed = GProfWatcherPrimed != 0;
	const uint32 LastFence = GProfWatcherLastFence;
	const uint32 PrimeFence = GProfWatcherPrimeFence;
	const uint64 Now = FPlatformTime::Cycles64();

	while (GProfPendingCount > 0)
	{
		FGXMProfScene& Scene = GProfPending[GProfPendingHead];
		if (!Scene.bEnded)
		{
			break;
		}

		if (Scene.DoneUs == 0 && GProfMode == 1)
		{
			if (bPrimed && ProfIsFenceReached(LastFence, Scene.Fence))
			{
				if (!ProfIsFenceReached(PrimeFence, Scene.Fence))
				{
					Scene.DoneUs = GProfCompletionUs[Scene.Fence & (GXMProf_CompletionSlots - 1)];
				}
			}
			else if (!bFlush && (Now - Scene.SubmitUs) < 1000000)
			{
				// Still on the GPU. Order matters for the queue figure, so nothing behind it goes out either.
				break;
			}
		}

		ProfEmitScene(Scene);

		GProfPendingHead = (GProfPendingHead + 1) % GXMProf_MaxPendingScenes;
		--GProfPendingCount;
	}
}

/*-----------------------------------------------------------------------------
	Recording lifetime.
-----------------------------------------------------------------------------*/

static const TCHAR* ProfSourceName(EGXMProfSource Source)
{
	switch (Source)
	{
	case EGXMProfSource::CommandLine:	return TEXT("commandline");
	case EGXMProfSource::CVar:	return TEXT("cvar");
	case EGXMProfSource::Combo:	return TEXT("combo");
	case EGXMProfSource::Razor:	return TEXT("razor");
	default:					return TEXT("none");
	}
}

static void ProfStartRecording(int32 Mode, EGXMProfSource Source, uint64 FrameLimit)
{
	GProfMode = Mode;
	GProfRecording = true;
	GProfDrainFramesLeft = 0;
	GProfSource = Source;
	GProfFrameLimit = FrameLimit;

	GProfPendingHead = 0;
	GProfPendingCount = 0;
	GProfOpenScene = nullptr;
	GProfOpenSection = -1;
	GProfNumSummary = 0;
	GProfFramesRecorded = 0;
	GProfFrameSumUs = 0;
	GProfGpuSumUs = 0;
	GProfLastDoneUs = 0;
	GProfDroppedScenes = 0;
	GProfUnknownDone = 0;
	GProfRecordingStartUs = FPlatformTime::Cycles64();
	FMemory::Memzero(GProfFrameWaitUs, sizeof(GProfFrameWaitUs));

	GProfSavedEmitDrawEvents = GEmitDrawEvents;
	GEmitDrawEvents = true;

	FPlatformAtomics::InterlockedExchange(&GProfWatcherWanted, (Mode == 1) ? 1 : 0);

	const int64 UnixTime = FDateTime::UtcNow().ToUnixTimestamp();
	const FString FileName = FString::Printf(TEXT("ux0:data/gxm_gpu_%lld.csv"), UnixTime);

	{
		ANSICHAR Control[256];
		const int32 Length = FCStringAnsi::Snprintf(Control, (int32)sizeof(Control), "%cOPEN %s\n", GXMProf_ControlByte, TCHAR_TO_ANSI(*FileName));
		ProfAppendText(Control, FMath::Min(Length, (int32)sizeof(Control) - 1));
	}

	ProfAppendLine("# gxm_gpu 1");
	ProfAppendLine("# mode,%d,source,%s,start_us,%llu,unix,%lld,frame,%llu", Mode, TCHAR_TO_ANSI(ProfSourceName(Source)),
		(unsigned long long)GProfRecordingStartUs, (long long)UnixTime,
		(unsigned long long)((GGXMRHI != nullptr) ? GGXMRHI->FrameCounter : 0));
	ProfAppendLine("# times are sceKernelGetProcessTimeWide microseconds. gpu_us = done - max(submit, previous done); queue_us = previous done - submit.");
	ProfAppendLine("# S,frame,fence,kind,width,height,draws,indices,open_us,endcall_us,submit_us,done_us,gpu_us,queue_us,serial_us,path,sections");
	ProfAppendLine("#   kind V = back buffer scene, O = off-screen; done_us 0 = completion not observed; serial_us = sceGxmFinish time in mode 2");
	ProfAppendLine("#   path = draw events open when the scene began, outer/inner; sections = innermost event=draws/indices issued under it");
	ProfAppendLine("# F,frame,start_us,end_us,scenes,game_us,render_us,beginscene_us,endscene_us,flip_us,throttle_us,present_us,render_stall_us,engine_sleep_us,dropped_scenes");
	ProfAppendLine("#   blocked times are this frame's except present_us and render_stall_us/engine_sleep_us, which the RHI samples one call later and so belong to the previous frame");

	UE_LOG(LogGXMGpuProfile, Display, TEXT("GPU profile recording started (%s, mode %d%s) -> %s"),
		ProfSourceName(Source), Mode, (Mode == 2) ? TEXT(" serial: frame rate will drop") : TEXT(""), *FileName);
}

static void ProfLogSummary()
{
	const double Frames = (double)FMath::Max<uint64>(GProfFramesRecorded, 1);

	UE_LOG(LogGXMGpuProfile, Display, TEXT("GPU profile: %llu frames, %.2f ms per frame, GPU busy %.2f ms per frame across the scenes timed. %u scenes without an observed completion, %u dropped, %u bytes of CSV dropped."),
		(unsigned long long)GProfFramesRecorded, (double)GProfFrameSumUs / Frames / 1000.0, (double)GProfGpuSumUs / Frames / 1000.0,
		GProfUnknownDone, GProfDroppedScenes, GProfDroppedBytes);

	// Slowest total first.
	int32 Order[GXMProf_MaxSummaryKeys];
	for (int32 Index = 0; Index < GProfNumSummary; ++Index)
	{
		Order[Index] = Index;
	}
	for (int32 Outer = 1; Outer < GProfNumSummary; ++Outer)
	{
		for (int32 Inner = Outer; Inner > 0 && GProfSummary[Order[Inner]].GpuUs > GProfSummary[Order[Inner - 1]].GpuUs; --Inner)
		{
			Swap(Order[Inner], Order[Inner - 1]);
		}
	}

	for (int32 Rank = 0; Rank < FMath::Min(GProfNumSummary, 16); ++Rank)
	{
		const FGXMProfSummary& Entry = GProfSummary[Order[Rank]];
		const double Count = (double)FMath::Max<uint32>(Entry.Count, 1);
		UE_LOG(LogGXMGpuProfile, Display, TEXT("  %5.2f ms/frame  mean %5.2f max %6.2f ms  x%.2f/frame  %c %4ux%-4u  %6.0f draws %8.0f indices  %s"),
			(double)Entry.GpuUs / Frames / 1000.0,
			(double)Entry.GpuUs / Count / 1000.0, (double)Entry.MaxGpuUs / 1000.0,
			Count / Frames,
			(TCHAR)Entry.Kind, Entry.Width, Entry.Height,
			(double)Entry.Draws / Count, (double)Entry.Indices / Count,
			ANSI_TO_TCHAR(Entry.Path));

		ProfAppendLine("# summary,%.3f,%.3f,%.3f,%.3f,%c,%u,%u,%.0f,%.0f,%s",
			(double)Entry.GpuUs / Frames / 1000.0, (double)Entry.GpuUs / Count / 1000.0, (double)Entry.MaxGpuUs / 1000.0,
			Count / Frames, Entry.Kind, Entry.Width, Entry.Height, (double)Entry.Draws / Count, (double)Entry.Indices / Count, Entry.Path);
	}
}

static void ProfStopRecording()
{
	GProfRecording = false;
	GProfDrainFramesLeft = GXMProf_DrainFrames;
	GProfOpenScene = nullptr;
	GProfOpenSection = -1;
	UE_LOG(LogGXMGpuProfile, Display, TEXT("GPU profile recording stopping (%s) after %llu frames; collecting the last completions."),
		ProfSourceName(GProfSource), (unsigned long long)GProfFramesRecorded);
}

static void ProfFinishRecording()
{
	ProfDrainPendingScenes(true);
	ProfLogSummary();
	ProfAppendLine("# end,frames,%llu", (unsigned long long)GProfFramesRecorded);

	ANSICHAR Control[16];
	const int32 Length = FCStringAnsi::Snprintf(Control, (int32)sizeof(Control), "%cCLOSE\n", GXMProf_ControlByte);
	ProfAppendText(Control, FMath::Min(Length, (int32)sizeof(Control) - 1));

	GEmitDrawEvents = GProfSavedEmitDrawEvents;
	FPlatformAtomics::InterlockedExchange(&GProfWatcherWanted, 0);
	GProfMode = 0;
	GProfSource = EGXMProfSource::None;
	GProfDrainFramesLeft = 0;
}

/*-----------------------------------------------------------------------------
	Hooks.
-----------------------------------------------------------------------------*/

void GXMGpuProfStartup()
{
	GProfText.Reserve(64 * 1024);

	int32 CmdLineFrames = 0;
	if (FParse::Value(FCommandLine::Get(), TEXT("GpuProfile="), CmdLineFrames) && CmdLineFrames > 0)
	{
		float DelaySeconds = 30.0f;
		FParse::Value(FCommandLine::Get(), TEXT("GpuProfileDelay="), DelaySeconds);

		GProfCmdLineFrames = (uint64)CmdLineFrames;
		GProfCmdLineAtUs = FPlatformTime::Cycles64() + (uint64)(FMath::Max(DelaySeconds, 0.0f) * 1000000.0f);
		GProfCmdLineMode = FParse::Param(FCommandLine::Get(), TEXT("GpuProfileSerial")) ? 2 : 1;

		UE_LOG(LogGXMGpuProfile, Display, TEXT("GPU profile armed from the command line: %d frames, mode %d, starting in %.0f s."),
			CmdLineFrames, GProfCmdLineMode, DelaySeconds);
	}

	GProfWriterThread = FRunnableThread::Create(&GProfWriter, TEXT("GXMGpuProfWriter"), 32 * 1024, TPri_BelowNormal, FPlatformAffinity::GetPoolThreadMask());
	GProfWatcherThread = FRunnableThread::Create(&GProfWatcher, TEXT("GXMGpuProfWatcher"), 16 * 1024, TPri_AboveNormal, FPlatformAffinity::GetPoolThreadMask());
	UE_LOG(LogGXMGpuProfile, Log, TEXT("GPU profiler ready: r.PSP2.GpuProfile 1, hold L+R+SELECT, or start a Razor capture with retail_razorconnect to record ux0:data/gxm_gpu_*.csv."));
}

void GXMGpuProfShutdown()
{
	if (GProfMode != 0)
	{
		ProfFinishRecording();
	}

	// The threads are told to stop but not joined. The watcher may be inside sceGxmWaitEvent() with the GPU
	// already idle, and a join there would hang shutdown; the process exit reclaims both.
	FPlatformAtomics::InterlockedExchange(&GProfStopThreads, 1);
}

void GXMGpuProfNoteEventPushed(const TCHAR* Name)
{
	if (GProfEventDepth < GXMProf_MaxEventDepth)
	{
		ProfCopySanitised(GProfEventNames[GProfEventDepth], GXMProf_MaxEventName, (Name != nullptr) ? TCHAR_TO_ANSI(Name) : "(null)");
	}
	++GProfEventDepth;

	if (GProfOpenScene != nullptr)
	{
		GProfOpenSection = ProfFindOrAddSection(*GProfOpenScene, ProfInnermostEventName());
	}
}

void GXMGpuProfNoteEventPopped()
{
	if (GProfEventDepth > 0)
	{
		--GProfEventDepth;
	}

	if (GProfOpenScene != nullptr)
	{
		GProfOpenSection = ProfFindOrAddSection(*GProfOpenScene, ProfInnermostEventName());
	}
}

void GXMGpuProfNoteSceneOpened(const TCHAR* What, uint32 Width, uint32 Height)
{
	++GProfScenesThisFrame;

	if (!GProfRecording)
	{
		return;
	}

	if (GProfPendingCount == GXMProf_MaxPendingScenes)
	{
		++GProfDroppedScenes;
		GProfOpenScene = nullptr;
		GProfOpenSection = -1;
		return;
	}

	FGXMProfScene& Scene = GProfPending[(GProfPendingHead + GProfPendingCount) % GXMProf_MaxPendingScenes];
	++GProfPendingCount;

	FMemory::Memzero(&Scene, STRUCT_OFFSET(FGXMProfScene, Path) + 1);
	Scene.Frame = (GGXMRHI != nullptr) ? GGXMRHI->FrameCounter : 0;
	Scene.Kind = (What != nullptr && What[0] == TEXT('v')) ? 'V' : 'O';
	Scene.Width = Width;
	Scene.Height = Height;
	Scene.OpenUs = FPlatformTime::Cycles64();

	int32 Used = 0;
	const int32 Depth = FMath::Min(GProfEventDepth, (int32)GXMProf_MaxEventDepth);
	for (int32 Level = 0; Level < Depth && Used < GXMProf_MaxPathChars - 1; ++Level)
	{
		if (Level > 0)
		{
			Scene.Path[Used++] = '/';
		}
		for (const ANSICHAR* Char = GProfEventNames[Level]; *Char != 0 && Used < GXMProf_MaxPathChars - 1; ++Char)
		{
			Scene.Path[Used++] = *Char;
		}
	}
	if (Used == 0)
	{
		FCStringAnsi::Strncpy(Scene.Path, "(none)", GXMProf_MaxPathChars);
	}
	else
	{
		Scene.Path[Used] = 0;
	}

	GProfOpenScene = &Scene;
	GProfOpenSection = ProfFindOrAddSection(Scene, ProfInnermostEventName());
}

void GXMGpuProfNoteDraw(uint32 IndexCount, uint32 NumInstances)
{
	if (GProfOpenScene == nullptr)
	{
		return;
	}

	const uint64 Indices = (uint64)IndexCount * (uint64)FMath::Max(NumInstances, 1u);
	++GProfOpenScene->Draws;
	GProfOpenScene->Indices += Indices;

	if (GProfOpenSection >= 0)
	{
		++GProfOpenScene->Sections[GProfOpenSection].Draws;
		GProfOpenScene->Sections[GProfOpenSection].Indices += Indices;
	}
}

void GXMGpuProfNoteSceneEnding()
{
	if (GProfOpenScene != nullptr)
	{
		GProfOpenScene->EndCallUs = FPlatformTime::Cycles64();
	}
}

void GXMGpuProfNoteSceneEnded(uint32 FenceValue)
{
	FGXMProfScene* const Scene = GProfOpenScene;
	GProfOpenScene = nullptr;
	GProfOpenSection = -1;

	if (Scene == nullptr)
	{
		return;
	}

	Scene->SubmitUs = FPlatformTime::Cycles64();
	Scene->Fence = FenceValue;
	Scene->bEnded = true;

	if (GProfMode == 2 && GGXMRHI != nullptr && GGXMRHI->Context != nullptr)
	{
		// Outside any scene, which sceGxmFinish() requires; every earlier scene is drained by it too, so the
		// time is this scene's alone.
		const uint64 FinishStartedUs = FPlatformTime::Cycles64();
		GXM_VERIFY(sceGxmFinish(GGXMRHI->Context));
		Scene->DoneUs = FPlatformTime::Cycles64();
		Scene->SerialUs = Scene->DoneUs - FinishStartedUs;
	}
}

void GXMGpuProfNoteWait(EGXMGpuProfWait Kind, double Seconds)
{
	if (GProfMode != 0 && Seconds > 0.0)
	{
		GProfFrameWaitUs[(int32)Kind] += (uint64)(Seconds * 1000000.0);
	}
}

void GXMGpuProfEndFrame()
{
	const uint64 Now = FPlatformTime::Cycles64();
	const uint64 Frame = (GGXMRHI != nullptr) ? GGXMRHI->FrameCounter : 0;

	if (GProfRecording)
	{
		if (GProfFrameStartUs != 0)
		{
			GProfFrameSumUs += Now - GProfFrameStartUs;
		}
		++GProfFramesRecorded;

		ProfAppendLine("F,%llu,%llu,%llu,%u,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%u",
			(unsigned long long)Frame, (unsigned long long)GProfFrameStartUs, (unsigned long long)Now, GProfScenesThisFrame,
			(unsigned long long)(FPlatformTime::ToMilliseconds(GGameThreadTime) * 1000.0),
			(unsigned long long)(FPlatformTime::ToMilliseconds(GRenderThreadTime) * 1000.0),
			(unsigned long long)GProfFrameWaitUs[(int32)EGXMGpuProfWait::BeginScene],
			(unsigned long long)GProfFrameWaitUs[(int32)EGXMGpuProfWait::EndScene],
			(unsigned long long)GProfFrameWaitUs[(int32)EGXMGpuProfWait::Flip],
			(unsigned long long)GProfFrameWaitUs[(int32)EGXMGpuProfWait::Throttle],
			(unsigned long long)GProfFrameWaitUs[(int32)EGXMGpuProfWait::Present],
			(unsigned long long)GProfFrameWaitUs[(int32)EGXMGpuProfWait::RenderStall],
			(unsigned long long)GProfFrameWaitUs[(int32)EGXMGpuProfWait::EngineSleep],
			GProfDroppedScenes);
	}

	if (GProfMode != 0)
	{
		ProfDrainPendingScenes(false);
	}

	FMemory::Memzero(GProfFrameWaitUs, sizeof(GProfFrameWaitUs));
	GProfFrameStartUs = Now;
	GProfScenesThisFrame = 0;

	if (!GProfRecording && GProfDrainFramesLeft > 0)
	{
		if (--GProfDrainFramesLeft == 0 || GProfPendingCount == 0)
		{
			ProfFinishRecording();
		}
		return;
	}

	// Triggers.
	const int32 CVarMode = FMath::Clamp(CVarPSP2GpuProfile.GetValueOnRenderThread(), 0, 2);
	const bool bCVarRose = (CVarMode != 0 && GProfLastCVarMode == 0);
	const bool bCVarFell = (CVarMode == 0 && GProfLastCVarMode != 0);
	GProfLastCVarMode = CVarMode;

	const bool bRazor = GProfRazorCapturing != 0;
	const bool bCombo = FPlatformAtomics::InterlockedExchange(&GProfComboPressed, 0) != 0;

	if (!bRazor)
	{
		GProfRazorLatched = false;
	}

	const bool bCmdLineDue = GProfCmdLineFrames != 0 && Now >= GProfCmdLineAtUs;

	if (!GProfRecording)
	{
		if (bCmdLineDue)
		{
			ProfStartRecording(GProfCmdLineMode, EGXMProfSource::CommandLine, GProfCmdLineFrames);
			GProfCmdLineFrames = 0;
		}
		else if (bCVarRose)
		{
			ProfStartRecording(CVarMode, EGXMProfSource::CVar, (uint64)FMath::Max(CVarPSP2GpuProfileFrames.GetValueOnRenderThread(), 0));
		}
		else if (bRazor && !GProfRazorLatched)
		{
			// Razor wants the frame rate it is looking at, so fence timing regardless of the console variable.
			ProfStartRecording(1, EGXMProfSource::Razor, (uint64)GXMProf_RazorMaxFrames);
		}
		else if (bCombo)
		{
			ProfStartRecording((CVarMode == 2) ? 2 : 1, EGXMProfSource::Combo, (uint64)GXMProf_ComboFrames);
		}
		return;
	}

	bool bStop = false;
	switch (GProfSource)
	{
	case EGXMProfSource::CommandLine:	bStop = false;	break;
	case EGXMProfSource::CVar:	bStop = bCVarFell;	break;
	case EGXMProfSource::Razor:	bStop = !bRazor;	break;
	case EGXMProfSource::Combo:	bStop = bCombo;		break;
	default:					bStop = true;		break;
	}

	if (GProfFrameLimit != 0 && GProfFramesRecorded >= GProfFrameLimit)
	{
		bStop = true;

		if (GProfSource == EGXMProfSource::Razor)
		{
			GProfRazorLatched = true;
			UE_LOG(LogGXMGpuProfile, Warning, TEXT("A Razor-flag recording reached %d frames and stopped. If no capture is running, delete ux0:data/rrc_capturing."), (int32)GXMProf_RazorMaxFrames);
		}
	}

	if (bStop)
	{
		ProfStopRecording();
	}
}

#endif // GXM_GPU_PROFILER
