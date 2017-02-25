# About

The goal of this project is to make it possible to generate/craft a new hashcat .hccap file from just the few information needed (essid, bssid, client mac, snonce, anonce, eapol, eapol size, key version and key mic).  
The format of the .hccap files is defined here: https://hashcat.net/wiki/doku.php?id=hccap

Note: for the newer [.hccapx format](https://hashcat.net/wiki/hccapx) you can use [craft_hccapx](https://github.com/philsmd/craft_hccapx)

# Requirements

Software:  
- Perl must be installed (should work on *nix and windows with perl installed)


# Installation and First Steps

* Clone this repository:  
    git clone https://github.com/philsmd/craft_hccap.git  
* Enter the repository root folder:  
    cd craft_hccap
* Run it:  
    ./craft_hccap.pl
* Check the generated file with (ocl)Hashcat:  
    ./oclHashcat64.bin -a 0 -m 2500 m02500.txt dict.txt

It is also possible to specify all the needed information directly on the command line (i.e. without entering the interactive mode).  
Each argument can be looked up in the usage/help screen:  
    ./craft_hccap.pl --help  
  
Furthermore, each argument can be used multiple times (except --help and --outfile).  
So for instance if you specify the full set of needed arguments twice:  
    ./craft_hccap.pl -o outfile -e "network 1" -b ... -e "network 2" -b ...  
then a .hccap file with 2 networks inside will be created (a so called multi-hccap file).  
  
The same can be done in interactive mode by answering the question accordingly.  

# Hacking

* More features
* CLEANUP the code, use more coding standards, everything is welcome (submit patches!)
* all bug fixes are welcome
* testing with different kinds of inputs
* solve and remove the TODOs
* and,and,and

# Credits and Contributors 
Credits go to:  
  
* philsmd, hashcat project

# License/Disclaimer

License: belongs to the PUBLIC DOMAIN, donated to hashcat, credits MUST go to hashcat and philsmd for their hard work. Thx  
  
Disclaimer: WE PROVIDE THE PROGRAM “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE Furthermore, NO GUARANTEES THAT IT WORKS FOR YOU AND WORKS CORRECTLY
