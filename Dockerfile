FROM centos:7
ARG src_file
RUN yum update -y && \
    yum install -y \
      python-virtualenv \
      python3 \
      python3-devel \
      gcc \
      krb5-devel &&\
    virtualenv -p /usr/bin/python3 /buildvenv &&\
    source /buildvenv/bin/activate &&\
    pip install --upgrade pip &&\
    pip install -r /builderdir/requirements.txt &&\
    pip install pyinstaller &&\
    pyinstaller --onefile /builderdir/${src_file} --distpath /builderdir/dist
