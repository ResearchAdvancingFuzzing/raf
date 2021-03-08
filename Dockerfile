FROM alpine:latest 

COPY spitfire /spitfire
WORKDIR /
CMD mv spitfire $NAMESPACE 
