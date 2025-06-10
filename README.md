# getsigner
python script to use the DLL to get the signer and validity of Windows executable file

1. Build getsigner.dll using Visual Studio in Windows.
2. Run verify.py with python as an example
```sh
       python Verify.py 
           File: [C:\windows\system32\drivers\afd.sys] signer(s) [{"Microsoft Windows": {"Issuer": "Microsoft Windows Production PCA 2011"},}]
```