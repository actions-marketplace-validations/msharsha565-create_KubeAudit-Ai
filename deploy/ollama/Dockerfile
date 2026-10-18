FROM ollama/ollama:latest

ENV OLLAMA_HOST=0.0.0.0:11434

# Start server temporarily in background to pre-bake the model into the image layer
RUN ollama serve & \
    SERVER_PID=$! && \
    sleep 3 && \
    ollama pull qwen2.5-coder:0.5b && \
    kill $SERVER_PID

EXPOSE 11434
ENTRYPOINT ["ollama", "serve"]
