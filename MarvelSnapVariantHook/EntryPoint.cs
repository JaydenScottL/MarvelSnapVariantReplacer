using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using EasyHook;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace MarvelSnapVariantHook
{
    public class ByteStringReplacer
    {
        public static byte[] ReplaceStringInBytes(byte[] data, string oldValue, string newValue, Encoding encoding)
        {
            byte[] oldBytes = encoding.GetBytes(oldValue);
            byte[] newBytes = encoding.GetBytes(newValue);
            List<byte> result = new List<byte>();

            for (int i = 0; i < data.Length; i++)
            {
                if (i + oldBytes.Length <= data.Length &&
                    data.Skip(i).Take(oldBytes.Length).SequenceEqual(oldBytes))
                {
                    result.AddRange(newBytes);
                    i += oldBytes.Length - 1; 
                }
                else
                {
                    result.Add(data[i]);
                }
            }

            return result.ToArray();
        }
    }

    public class EntryPoint : IEntryPoint
    {
        JArray variants;

        private readonly Queue<string> dataExtracted = new Queue<string>();

        public IntPtr TargetAddress { get; set; }

        public Process TargetProcess { get; set; }

        public string directory;

        public EntryPoint(RemoteHooking.IContext context, string dir)
        {
            TargetProcess = Process.GetProcessesByName("SNAP")[0];
            directory = dir;
            string jsonString = File.ReadAllText(directory + "\\variants.json");
            variants = JArray.Parse(jsonString);
        }

        public void WebsocketDataRecievedHook(IntPtr socket, IntPtr data, int offset, int length)
        {
            byte[] numArray = new byte[length];
            SigScanSharp.Win32.ReadProcessMemory(TargetProcess.Handle, (ulong)data.ToInt64() + 32UL, numArray, length);

            Encoding encoding = Encoding.UTF8; 

            string receivedString = encoding.GetString(numArray);
            byte[] copiedArray = new byte[numArray.Length];
            numArray.CopyTo(copiedArray, 0);
            bool flag = false;

            try
            {

                if (variants != null)
                {

                    foreach (JToken token in variants)
                    {
                        if (token is JObject jObject)
                        {
                            if (receivedString.Contains(jObject.Properties().FirstOrDefault().Name))
                            {
                                copiedArray = ByteStringReplacer.ReplaceStringInBytes(copiedArray, "\"ArtVariantDefId\":\"" + jObject.Properties().FirstOrDefault().Name + "\",", "\"ArtVariantDefId\":\"" + jObject.Properties().FirstOrDefault().Value + "\",", encoding);
                                flag = true;
                            }
                        }
                    }

                }

                if (flag)
                {
                    byte[] modifiedByteArray = encoding.GetBytes(receivedString);
                    if (copiedArray.Length == length)
                    {
                        bool s = SigScanSharp.Win32.WriteProcessMemory(TargetProcess.Handle, (ulong)data.ToInt64() + 32UL, copiedArray, length);
                    }
                }
            }catch(Exception ex)
            {
                File.AppendAllText(directory + "\\log.txt", ex.Message + Environment.NewLine);
            }

            (Marshal.GetDelegateForFunctionPointer(TargetAddress, typeof(WebsocketDataRecieved_Delegate)) as WebsocketDataRecieved_Delegate)(socket, data, offset, length);
        }

        public IntPtr GetHookTarget()
        {
            Process process = Process.GetProcessesByName("SNAP")[0];
            SigScanSharp sigScanSharp = new SigScanSharp(process.Handle);
            ProcessModule targetModule = null;

            foreach (ProcessModule module in (ReadOnlyCollectionBase)process.Modules)
            {
                if (module.FileName.Contains("GameAssembly"))
                {
                    targetModule = module;
                    break;
                }
            }

            sigScanSharp.SelectModule(targetModule);
            sigScanSharp.AddPattern("DataReceived", "40 53 55 56 41 54 41 55 41 57 48 83 EC 38 80 3D ? ? ? ? 00 41 8B F1 45 8B F8");
            return new IntPtr((long)sigScanSharp.FindPatterns(out long _)["DataReceived"]);
        }

        public void Run(RemoteHooking.IContext context,string dir)
        {
            TargetAddress = GetHookTarget();
            
            LocalHook localHook = null;

            try
            {
                localHook = LocalHook.Create(TargetAddress, new WebsocketDataRecieved_Delegate(WebsocketDataRecievedHook), this);
                localHook.ThreadACL.SetExclusiveACL(new int[1]);
                
            }
            catch (Exception)
            {
            }

            try
            {
                while (true)
                {
                    Thread.Sleep(500);
                    
                }
            }
            catch
            {
            }

            localHook.Dispose();
            LocalHook.Release();
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        private delegate void WebsocketDataRecieved_Delegate(
          IntPtr socket,
          IntPtr data,
          int offset,
          int length);

        
    }
}
