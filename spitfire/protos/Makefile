

knowledge_base_pb2.py knowledge_base_pb2_grpc.py:
	python3 -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. ./knowledge_base.proto

clean:
	rm knowledge_base_pb2.py knowledge_base_pb2_grpc.py
