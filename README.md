# getsigner
python script to use the DLL to get the signer and validity of Windows executable file

## Functionality
1. Digital Signature Check: The DLL inspects the provided executable file to determine if it has a digital signature.
2. Signature Validation: If a signature is present, the DLL verifies its validity, checking aspects such as the certificate chain and expiration date.
3. Python Interface: The Verify.py script provides a command-line interface for users to specify the path of the executable file and receive information about its digital signature and validity.

## Usage
To use the getsigner tool:
1. Build the DLL: Open the solution file (getsigner.sln) in Microsoft Visual Studio and build the project to generate getsigner.dll.
2. Place the DLL: Ensure that getsigner.dll is in the same directory as Verify.py or in a directory included in your system's PATH.
3. Run the Python Script: Execute Verify.py from the command line
```sh
       python Verify.py 
           File: [C:\windows\system32\drivers\afd.sys] signer(s) [{"Microsoft Windows": {"Issuer": "Microsoft Windows Production PCA 2011"},}]
```