# SysPulse

Windows sistem izleme ve bellek temizleme aracı (C#, WinForms).

## Gereksinimler
- Windows, .NET Framework 4.x
- Yönetici hakları (bellek temizleme işlemleri için)

## Derleme
```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:winexe /win32icon:app.ico /out:SysPulse.exe /r:System.Management.dll /r:System.ServiceProcess.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll SysPulse.cs
```

## Lisans
MIT
