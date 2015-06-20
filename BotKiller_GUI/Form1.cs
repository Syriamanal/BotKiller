using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace BotKiller_GUI
{
    public partial class Form1 : Form
    {

        Dictionary<string, string> sigDatabase = new Dictionary<string,string>()
        {
            {"Nanocore", "nanocore client"},
            {"IM3", "ClientMain\0Imminent"},
            {"LuminosityLink", "L\0u\0m\0i\0n\0o\0s\0i\0t\0y\0L\0i\0n\0k\0 \0i\0s\0 \0R\0u\0n\0n\0i\0n\0g"}
        };

        [StructLayout(LayoutKind.Sequential)]
        struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public uint RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        enum AccessType
        {
            PAGE_NOACCESS = 0x1,
            MEM_MAPPED = 0x40000,
            MEM_PRIVATE = 0x20000,
            COMMIT = 0x1000
        }

        enum Thread_access
        {
            ALL_ACCESS = 0x1f03ff
        }



        [DllImport("kernel32.dll")]
        private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, int size, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        private static extern bool IsWow64Process(IntPtr handle, out bool proc);

        [DllImport("kernel32.dll")]
        private static extern int SuspendThread(IntPtr handle);

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenThread(int access, bool bInheritHandle, int threadId);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(int access, bool inherit, int procId);

        [DllImport("ntdll.dll")]
        public static extern void NtQueryInformationProcess(IntPtr handle, int ProcessInfoClass, ref int procInfo, int ProcessInfomationLength, out ulong ReturnLength);

        public Form1()
        {
            InitializeComponent();
            
        }
        Thread workingThread;
        private void button1_Click(object sender, EventArgs e)
        {
            SetButtonness(false);
            workingThread = new Thread(seekMemThread);
            workingThread.Start();
        }

        void seekMemThread()
        {
            int blocksize = 1000;
            Process[] currentProcesses = Process.GetProcesses();
            MEMORY_BASIC_INFORMATION mi;
            uint memoryScanned = 0;
            byte[] buffer = new byte[blocksize];
            int t_int;
            bool is64;

            int longestSig = 0;
            foreach (var swSig in sigDatabase)
            {
                if (swSig.Value.Length > longestSig)
                    longestSig = swSig.Value.Length;
            }
            if (longestSig <= blocksize)
                blocksize = longestSig + 1;

            foreach (Process p in currentProcesses)
            {
                memoryScanned = 0;
                try
                {
                    IsWow64Process(p.Handle, out is64);
                    if (p.Handle == IntPtr.Zero)
                    {
                        // Console.WriteLine("Ignred process {0}", p.ProcessName);
                        continue;
                    }
                }
                catch
                {
                    continue;
                }
                //Console.WriteLine("[{0}] Scanning...", p.Id);
                mi = new MEMORY_BASIC_INFORMATION();
                try
                {
                    bool breakProc = false;
                    while (VirtualQueryEx(p.Handle, (IntPtr)memoryScanned, out mi, (uint)blocksize) != 0)
                    {
                        breakProc = false;
                        if ((mi.Type == (int)AccessType.MEM_PRIVATE || mi.Type == (int)AccessType.MEM_MAPPED) && mi.State == (int)AccessType.COMMIT && mi.Protect != (int)AccessType.PAGE_NOACCESS)
                        {
                            for (int i = (int)mi.BaseAddress; i < (int)mi.BaseAddress + mi.RegionSize; i += blocksize - longestSig)
                            {
                                if (ReadProcessMemory(p.Handle, (IntPtr)i, buffer, blocksize, out t_int))
                                {
                                    foreach (var swSig in sigDatabase)
                                    {
                                        if (System.Text.Encoding.UTF8.GetString(buffer).ToLower().Contains(swSig.Value.ToLower()))
                                        {
                                            MWFound m = new MWFound();
                                            m.Proc = p;
                                            m.DisplayMember = swSig.Key;
                                            AddToList(m);
                                            breakProc = true;
                                            break;
                                        }
                                    }
                                }
                            }
                            if (breakProc)
                                break;
                        }
                        memoryScanned += mi.RegionSize;
                    }
                }
                catch
                {
                    continue;
                }
            }
            SetButtonness(true);
        }

        bool ContailsAlredy(MWFound p)
        {
            foreach (ListViewItem i in listView1.Items)
            {
                MWFound mw = (MWFound)i.Tag;
                if (mw.Proc.Id == p.Proc.Id)
                    return true;
            }
            return false;
        }

        void AddToList(MWFound p)
        {
            this.Invoke((MethodInvoker)delegate()
            {
                if (!ContailsAlredy(p))
                {
                    ListViewItem i = new ListViewItem(p.Proc.ProcessName);
                    i.SubItems.Add(p.DisplayMember);
                    i.SubItems.Add(p.Proc.Id.ToString());
                    try
                    {
                        i.SubItems.Add(p.Proc.Modules[0].FileName);
                    }
                    catch
                    {
                        i.SubItems.Add("Access denied.");
                    }
                    i.Tag = p;
                    listView1.Items.Add(i);
                }
            });
        }

        void SetButtonness(bool  e)
        {
            this.Invoke((MethodInvoker)delegate()
            {
                button1.Enabled = e;
                if (!e)
                    button1.Text = "Scanning...";
                else
                    button1.Text = "Scan";
            });
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (workingThread != null)
                workingThread.Abort();
        }
    }
}
