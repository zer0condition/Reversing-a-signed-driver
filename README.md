<h1>Reverse Engineering a Signed Kernel Driver</h1>
<h2>Introduction:</h2>
<p>Recently, I was approached by a Discord user who requested that I crack a P2C which i will not name, as he had been banned by them after experiencing some difficulties while attempting to use their services. Although initially hesitant, my boredom got the better of me, and I decided to take a look. I was not surprised to find that the loader had been packed and virtualized using one of the latest <b>VMProtect3</b> versions, which made things a bit more complicated. However, through dynamic analysis, I discovered a binary being dropped to disk on my C:\Windows\System32 directory. I expected this to be an executable, but it had a .sys extension. Upon closer inspection, I found the driver's size to be around 2MB, which is unusual for drivers, and its digital certificate had been signed with a revoked/expired EV certificate from a Chinese company called <b>'Binzhoushi Yongyu Feed Co.,LTd.'</b></p>
<img src="https://i.imgur.com/J8wchy4.png" alt="deviceo" width="70%">

<h2>Investigation:</h2>
<p>Further investigation revealed that the driver's timestamp was from 2015, which was unusual. I decided to load the driver into IDA and found that it had been packed and virtualized with VMProtect3 once again.</p>
<img src="https://i.imgur.com/YNXvkUv.png" alt="deviceo" width="70%">


<p> Unfortunately, the entry point was virtualized, so I had to enlist the help of a friend to divirtualize the binary using specialized tools. After obtaining the devirtualized binary, I delved further into the driver's internals and discovered that it used I/Os for communication, which is not out of the ordinary. </p> 
<p>Eventually, I found the driver object's reference, followed a sub-function, and located the IRP/Dispatch handler of the driver.</p>

<div style="display:flex; align-items:center;">
  <img src="https://i.imgur.com/9KGoS40.png" alt="deviceo" style="display:inline-block; width:180px;">
  <img src="https://i.imgur.com/KxgaJws.png" alt="device1" style="display:inline-block; width:170px; float:left;">
  <p><b>sub_1400011D0 is the dispatcher</b></p>
</div>


<p>While the functionality wasn't too complicated, the control code passed through the stack location was "encrypted" with some XOR and bitwise operations. The driver controller example program explains how it works. </p> 
<img src="https://i.imgur.com/wf64H8f.png" alt="deviceo">

<h2>IOCTLs and Functionalities:</h2>
<p> I decided to look into the functionalities of the drivers and their control codes. </p>

<h4>GetProcessBaseAddresss:</h4>
<p><b>0x13370400</b>: This was the first ioctl code I came across, which uses a structure with two variables sent through the IRP SystemBuffer. A buffer is returned to the usermode after the request. It takes a process id integer parameter, which is used for PsLookupProcessByProcessId() to get the PE process of the target process and passed into PsGetProcessSectionBaseAddress(), which returns the ImageSectionBaseAddress of the process. The base address is then accessed from the usermode with the second variable inside the structure.</p>
<img src="https://i.imgur.com/aoIwRT3.png" alt="deviceo">

<h4>ReadProcessMemory:</h4>
<p><b>0x13370800</b>: This was the second ioctl code found, It also uses a structure passed from the SystemBuffer but of a different size, containing an int, uintptr_t, uintptr_t and size_t respectively. The first parameter was later found out to be a process id passed from the usermode request, the second is the source address, the third is the buffer, and lastly, the size. </p> 
<img src="https://i.imgur.com/jevpmlw.png" alt="deviceo">

<p>Further analysis uncovered the purpose of the two function calls in here. The first function call sets up the functions required for reading/writing process memory: </p>
<div style="display:flex; align-items:center;">
  <img src="https://i.imgur.com/AUBnFlN.png" alt="deviceo" style="display:inline-block;">
  <img src="https://i.imgur.com/fH2jbOh.png" alt="device1" style="display:inline-block;">
</div>

The second function call reads the process memory through physical memory. It takes the source address, buffer, size, and a variable that returns a value but is not used further: </p>
<img src="https://i.imgur.com/q0O8EwJ.png" alt="deviceo">

<p> Taking a look inside the function, there is nothing that complicated; it converts the virtual address passed and converts it into a physical address (linear translation) and is used in MmCopyMemory for reading the process memory.</p>
<img src="https://i.imgur.com/ozft12C.png" alt="deviceo">

<h4>WriteProcessMemory</h4>
<p> <b>0x13370C00</b>: This was the final code found, which is for writing process memory. It takes a structure of the same size as the readprocessmemory with the same variables. The same function called before in the read request handler sets up the write function to be used, and the write function itself is called after that, taking the source address, buffer, size, and a variable that returns a value but is not used further. </p>
<img src="https://i.imgur.com/hcenajT.png" alt="deviceo">

<p>The write function takes the virtual address passed and converts it into a physical address (linear translation) and is used in MmMapIoSpaceEx for writing/mapping values to the process memory.</p>
<img src="https://i.imgur.com/rYDFhhl.png" alt="deviceo">
<img src="https://i.imgur.com/sbVJfYw.png" alt="deviceo">

<h2>Conclusion:</h2>
<p>Overall, though not certain on how the driver is being allowed to be loaded on my Windows 11 and 10 systems despite having a revoked/expired certificate, reverse engineering the signed kernel driver was an interesting and challenging task. It involved dynamic analysis, divirtualization, and investigation into the driver's internals to uncover its functionalities and control codes. It's important to note that reverse engineering and cracking software without permission is illegal and can have severe consequences. As such, it's crucial to always act ethically and with integrity when dealing with software and its security.</p>
<p> This repository contains the signed binary along with an example program on how to send requests to this driver and technically use it. <br>
<b> Use at own risk. </b> </p> 
