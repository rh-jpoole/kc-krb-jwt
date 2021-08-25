FROM quay.io/centos/centos:7
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
    /builderdir/install.sh
