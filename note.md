Wireshark will load the plugins following the order of filename.
So dfsc.lua will be loaded first and then ndiswan.lua.
In this case, DFSC protocol inside Ras-NdisWan will not be dissected.
To avoid this, we need to make dfsc.lua get loaded after ndiswan.lua.
Just rename the files with numbers or characters at the beginning, e.g. "a-ndiswan.lua", "z-dfsc.lua".