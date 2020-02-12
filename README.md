# RAF: Research Advancing Fuzzing

# Need to build all the images first 
docker build -t hpreslier/knowledge-base:v1 -f spitfire/knowledge_base/ .
docker build -t hpreslier/knowledge-base-test:v1 -f spitfire/knowledge_base_test/ . 
docker push

minikube start 

helm install stable/postgresql 

kubectl apply -f config.yaml



Ok to use google rpc you have to

sudo python3.6 -m pip install grpcio
sudo python3.6 -m pip install grpcio-tools
sudo python3.6 -m pip install docker
sudo python3.6 -m pip install hydra-core --upgrade


