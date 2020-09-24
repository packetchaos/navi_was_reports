# navi_was_reports
Tenable WAS reporting solution using Flask

    *** This tool is not an officially supported Tenable project ***

    *** Use of this tool is subject to the terms and conditions identified below,
    and is not subject to any license agreement you may have with Tenable ***

## Directions

### Pull the Docker container
    docker pull silentninja/navi:was

### Run the Docker Container.
    docker run -it -e "access_key=<access key>" -e "secret_key=<secret_key>" -p 5004:5004 silentninja/navi:was


