FROM centos:7
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
    pip install -r /getjwtsrc/requirements.txt &&\
    pip install pyinstaller &&\
    pyinstaller --onefile /getjwtsrc/getjwt.py --distpath /getjwtsrc/dist
