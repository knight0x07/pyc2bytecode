# pyc2bytecode:

A Python Bytecode Disassembler helping reverse engineers in dissecting Python binaries by disassembling and analyzing the compiled python byte-code(.pyc) files across all python versions (including Python 3.10.*)

## Usage: 

To run pyc2bytecode:
```
> Console Disassembled Output: python pyc2bytecode.py -p <pyc_file_path>
> Save Disassembled Output to a file: python pyc2bytecode.py -p <pyc_file_path> -o <output_file_path> 
```
## Demonstration:

**pyc2bytecode** can be used by researchers for reverse engineering Malicious Python Binaries and tear them apart in order to understand the inner workings of the binary statically.

We execute pyc2bytecode.py against **onlyfans.pyc** which is extracted from a recent Python ransomware sample masquerading as an **OnlyFans** executable in the wild using [pyinstxtractor.py](https://github.com/countercept/python-exe-unpacker/blob/master/pyinstxtractor.py)

Following are the analysis results extracted post execution of **pyc2bytecode**:

![2](https://user-images.githubusercontent.com/60843949/149174687-0191b9f2-89e0-493e-b140-0f3b2adc5af6.PNG)

![3](https://user-images.githubusercontent.com/60843949/149175102-fe0c9214-c7cd-4f78-87a0-aa25c4571196.PNG)

![7](https://user-images.githubusercontent.com/60843949/149175411-fc4606c4-4f42-49ad-9724-4d60ba81e7fa.PNG)

![8](https://user-images.githubusercontent.com/60843949/149175512-6c577c97-d4d3-4f8f-a409-cb327eb84a23.PNG)

![9](https://user-images.githubusercontent.com/60843949/149175534-f3bb9f11-8ca7-4564-8281-ebc7d32a6e34.PNG)

**Extract the Disassembled output into a text file**

![output-file](https://user-images.githubusercontent.com/60843949/149175676-34e76764-c7e9-4990-8c4c-ef3cda214450.PNG)

![10](https://user-images.githubusercontent.com/60843949/149175797-8075b3e1-61e5-4645-a693-688539c36b6a.PNG)


## Future Development:

- Develop Python decompiler for recent python versions by using pyc2bytecode (Need to DIS it up :p)

## Credits & References:

i) https://github.com/google/pytype/blob/main/pytype/pyc/magic.py - Magic Numbers	</br>
ii) https://nedbatchelder.com/blog/200804/the_structure_of_pyc_files.html - PYC structure	</br>
iii) https://docs.python.org/3/library/dis.html - DIS	</br>
iv) https://docs.python.org/3/library/marshal.html- Marshal	</br>

**Thankyou, Feedback would be greatly appreciated! hope you like the tool :) - knight!**


