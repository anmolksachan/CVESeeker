![Banner](https://github.com/anmolksachan/CVESeeker/assets/60771253/338996fe-de1b-4402-9e47-cb4951423b52)

# CVE Seeker - Unveiling Cyber Threats: From Assets to Vulnerability Insights

A comprehensive tool for passive asset scanning, identifying associated CVEs, and finding publicly available proof-of-concept (POC) exploits on GitHub.

## Features

- The whole script uses the passive method to identify CVE via Shodan's free API.
- Resolves domains to IPs.
- Identifies open ports for each IP.
- Fetches CVEs for each IP.
- Retrieves POCs for identified CVEs (Supports Github currently).
- Reverse CVE to POC Lookup

## Installation

1. **Clone the repository:**

    ```sh
    git clone https://github.com/anmolksachan/CVESeeker && cd CVESeeker  
    ```

2. **Install the required libraries:**

    ```sh
    pip3 install -r requirements.txt
    ```

3. **Ensure you have `colorama` installed for colorful terminal output:**

    ```sh
    pip install colorama
    ```
4. **One line installer:**

   ```sh
   git clone https://github.com/anmolksachan/CVESeeker && cd CVESeeker && pip3 install -r requirements.txt && echo "We are ready to seek sailor! " && python3 cveSeeker.py
   ```
   
## Usage

```sh
$ python3 cveSeeker.py --file <input_file> --project <project_name>
--file:             Input file containing domains / IPs (one per line).
--project:          Project name for storing results.
-cve CVE-ID         CVE ID for fetching POCs
```

## Example
![image](https://github.com/anmolksachan/CVESeeker/assets/60771253/59c61407-2d94-4610-8c08-c39048b7c52a)

## Passive Scanner : Asset -> CVE -> POC Lookup
![CVESeekerPOCDemo-PassivenmaplikescannertofetchCVEsPOCfromgithub](https://github.com/anmolksachan/CVESeeker/assets/60771253/72e89c78-e22b-4dbf-b7eb-527bd26be4b2)

## CVE Reverse POC Lookup
![image](https://github.com/anmolksachan/CVESeeker/assets/60771253/8366c17e-3408-4ad8-8e2e-c27cfc4e5f9e)

## Watch Full Demo Here
[Watch Here!](https://vimeo.com/960905849)

## License
This project is licensed - see the LICENSE file for details.

## Note
Feel free to enhance, modify, or contribute to this script to suit your needs and explore more security-related projects!

## __Want to support my work?__
Give me a Star in the repository or follow me [@FR13ND0x7F](https://twitter.com/fr13nd0x7f) , that's enough for me :P

## Contact
Shoot my DM : [@FR13ND0x7F](https://twitter.com/fr13nd0x7f)

Coded with ❤️ by Anmol K Sachan (@FR13ND0x7F)
