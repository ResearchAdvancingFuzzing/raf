FROM ubuntu

COPY spitfire /tmp
WORKDIR /
CMD cp -r /tmp/* /spitfire 
#CMD mkdir /shared/spitfire && cp -r /tmp/* /shared/spitfire
#$SPITFIRE
#&& cp -r /tmp/* /shared/spitfire
#$SPITFIRE
#/spitfire

#COPY spitfire/protos /tmp 
#CMD cp /tmp /spitfire/protos 
