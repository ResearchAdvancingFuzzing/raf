FROM ubuntu

COPY spitfire /tmp
CMD cp -r /tmp/* /spitfire

#COPY spitfire/protos /tmp 
#CMD cp /tmp /spitfire/protos 
