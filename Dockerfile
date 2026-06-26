# Build from ~/Projects:
#   docker build -f raphael-identity/Dockerfile .
FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir uv
COPY raphael-contracts /deps/raphael-contracts
RUN uv pip install --system /deps/raphael-contracts
COPY raphael-identity/pyproject.toml raphael-identity/README.md ./
COPY raphael-identity/src ./src
RUN python3 -c "import re; from pathlib import Path; p=Path('pyproject.toml'); p.write_text(re.sub(r'\n\[tool\.uv\.sources\][^\[]*','\n',p.read_text(),flags=re.S))"
RUN uv pip install --system -e .
ENV RAPHAEL_SERVICE_PORT=8081
EXPOSE 8081
CMD ["uvicorn", "raphael_identity.app:app", "--host", "0.0.0.0", "--port", "8081"]
