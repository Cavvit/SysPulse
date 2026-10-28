# SysPulse

Windows sistem izleme ve bellek temizleme aracı (C#, WinForms).

## Gereksinimler
- Windows, .NET Framework 4.x
- Yönetici hakları (bellek temizleme işlemleri için)

## Derleme
```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:winexe /win32icon:app.ico /out:SysPulse.exe /r:System.Management.dll /r:System.ServiceProcess.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll SysPulse.cs
```

## Uyumluluk
- Geliştirildiği ve test edildiği cihaz: **ASUS TUF A15** (AMD Ryzen 7 4800H, NVIDIA GTX 1660 Ti), Windows.
- RAM temizleme ve süreç/servis yönetimi standart Windows API'lerini kullanır, diğer PC'lerde de çalışması beklenir.
- ASUS servisleri (Armoury Crate, Aura, G-Helper vb.) cihaza özeldir. ASUS olmayan cihazlarda bu girdiler atlanır.
- MSI, Lenovo, Dell, HP gibi markaların servisleri tanınmaz. Diğer cihazlarda **test edilmemiştir**.

## Uyarı
- Uygulama **yönetici hakkı** ister.
- Bazı servisleri durdurabilir (ör. Aura, ekran yenileme). Bu, sürücülerin, kısayol tuşlarının veya RGB ayarlarının çalışmasını etkileyebilir. Durdurulan servisler yeniden başlatma ile geri gelir.
- Yazılım "olduğu gibi" sunulur, kullanım sorumluluğu kullanıcıya aittir (bkz. [LICENSE](LICENSE)).

## Lisans
MIT
