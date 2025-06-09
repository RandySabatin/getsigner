import ctypes
import os 

libName = "getsigner.dll"
ToolAPI = ctypes.CDLL(libName)

ToolAPI.GetFileSignature.argtypes = [ctypes.c_char_p, ctypes.c_char_p,ctypes.c_size_t]
ToolAPI.GetFileSignature.restype = ctypes.c_int

ToolAPI.DeleteBuffer.argtypes = [ctypes.c_char_p, ctypes.c_char_p,ctypes.c_size_t]
ToolAPI.DeleteBuffer.restype = ctypes.c_int

filename =  "C:\\codes\\getsigner\\123\\tmactmon.sys"
bytes_filename =  filename.encode() # convert to bytes

result = ctypes.create_string_buffer(1000)
int_return = ToolAPI.GetFileSignature(bytes_filename, result, ctypes.sizeof(result))

str_result = result.value.decode("UTF-8") # convert to string
print("File: [%s] signer(s) [%s]" %(filename, str_result))

dict_result = eval(str_result) # convert to dictionary

#Delete the buffer pointer and unload dll (although python's garbage collector never really unload the dll)
#int_return = ToolAPI.DeleteBuffer(bytes_filename, result, ctypes.sizeof(result))
#del ToolAPI    
