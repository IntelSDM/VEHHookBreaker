# VEH Hook Breaker Pass
Built for LLVM 19.1 - Windows x64 <br> <br>

We utilize a trick with how windows stores exception information, exception information is written in an 0x1000 range below the stack. So when we write to it, if an exception occurs, it overwrites our information <br>
This has been done in denuvo for a while but only publicly documented by this legend: <br>
[Connor Jay's Denuvo Blog](https://connorjaydunn.github.io/blog/posts/denuvo-analysis/) <br>
Unlike denuvo though, we use it in our code, not in a VM. This means we don't have the downsides of slow VM execution, we only get the upsides of breaking VEHs. <br>
This will also break inline hooks that use any callbacks or downstream call any exception based code. It makes hooking and runtime attacking your program HELL! <br>
This also is directly affected by APCs too. 

## The Methodology

<img width="685" height="930" alt="image" src="https://github.com/user-attachments/assets/99eefd38-ccd2-4e13-9ed2-e08997e09280" />

var_318 is -318 <br>
Stack frame is 118 <br>
Each access to rsp+118h+var_318 is rsp-200 <br>
Every time we call/ leave scope, we pocket the value out of rsp - 200 <br>
Then when we unpocket it and use it to decrypt constants. <br>
This means at any scope, an exception or function is called that our code wasn't designed for. It will crash as the decryption is false and rsp - 200 is different. 

## Annotations
```c
__attribute__((annotate("vehbreaker")))
``` 
* Applies protection to constants in function

## How To Build
* Download [LLVM 19.1](https://github.com/llvm/llvm-project/releases/tag/llvmorg-19.1.0)
* Download [VCPKG](https://github.com/microsoft/vcpkg)
* VCPKG install asmjit
* Open build.bat in a text editor.
* Find the LLVM 19.1 references in the command line, Change them to your file path.
* Find the VCPKG references in the command line, Change them to your file path.
* Run the build script
* Build your application with the ``` -load-pass-plugin ``` Param to the FunctionPass.dll
