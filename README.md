# navi_was_reports
Tenable WAS reporting solution using Flask

    *** This tool is not an officially supported Tenable project ***

    *** Use of this tool is subject to the terms and conditions identified below,
    and is not subject to any license agreement you may have with Tenable ***

# Deployment Options
* Use Docker to run as a Service "-d" detatched
* Use Docker in interactive mode "-it" to run in a temporary fashion
* Run as a Python script for one-time reporting


## Use Docker:
### Install Docker
Follow the Docker Documentation for your Chosen OS:

    https://docs.docker.com/get-docker/

### Pull the Docker container
    docker pull silentninja/navi:was

### Run the Docker Container.
Replace \<access Key> and \<secret key> with your Tenable.io API keys.

    docker run -it -e "access_key=<access key>" -e "secret_key=<secret key>" -e "<days to limit>" -p 5004:5004 silentninja/navi:was

## Run Using Python
### Install All of the required packages and libraries
    Python 3.6+
    Git
    python requests lib
    python flask lib

### Install Python 3.6 or greater.
Follow the Python Documentation for your chosen OS:

    https://www.python.org/downloads/

### Install Git
Follow the Python Documentation for your chosen OS:

    https://git-scm.com/downloads

### Install Python Libraries
    pip3 install requests
    pip3 install flask

### Clone the repository
    git clone https://github.com/packetchaos/navi_was_reports.git

### Run the Script
    python3 ./was_report_gen.py <access_key> <secret_key> <days_to_limit>
