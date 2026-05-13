import httpx
import json
import yaml
from typing import List, Dict, Optional


async def fetch_spec(spec_url: str) -> Optional[Dict]:
    """
    Fetches an OpenAPI/Swagger spec from a URL.
    Supports both JSON and YAML formats.
    """
    try:
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            resp = await client.get(spec_url)
            content_type = resp.headers.get("content-type", "")

            if "yaml" in content_type or spec_url.endswith((".yaml", ".yml")):
                return yaml.safe_load(resp.text)
            else:
                return resp.json()
    except Exception as e:
        return None


def parse_endpoints(spec: Dict) -> List[Dict]:
    """
    Parses an OpenAPI 2.0 (Swagger) or OpenAPI 3.x spec
    and returns a flat list of endpoints with method, path, and parameters.
    """
    endpoints = []

    # Detect version
    openapi_version = spec.get("openapi", spec.get("swagger", ""))

    # Get base URL
    base_url = ""
    if openapi_version.startswith("3"):
        servers = spec.get("servers", [])
        base_url = servers[0].get("url", "") if servers else ""
    else:
        host = spec.get("host", "")
        base_path = spec.get("basePath", "/")
        schemes = spec.get("schemes", ["https"])
        base_url = f"{schemes[0]}://{host}{base_path}"

    paths = spec.get("paths", {})

    for path, path_item in paths.items():
        for method in ["get", "post", "put", "patch", "delete", "options"]:
            operation = path_item.get(method)
            if not operation:
                continue

            # Extract parameters
            parameters = operation.get("parameters", [])
            query_params = {}
            body_fields = {}

            for param in parameters:
                param_in = param.get("in", "")
                param_name = param.get("name", "")
                param_default = param.get("schema", {}).get("default", "test")

                if param_in == "query":
                    query_params[param_name] = param_default
                elif param_in == "body":
                    body_fields[param_name] = param_default

            # OpenAPI 3.x requestBody
            request_body = operation.get("requestBody", {})
            if request_body:
                content = request_body.get("content", {})
                json_content = content.get("application/json", {})
                schema = json_content.get("schema", {})
                properties = schema.get("properties", {})
                for prop_name, prop_schema in properties.items():
                    body_fields[prop_name] = prop_schema.get("default", "test")

            full_url = base_url.rstrip("/") + path

            endpoints.append({
                "url": full_url,
                "method": method.upper(),
                "params": query_params,
                "body": body_fields,
                "operation_id": operation.get("operationId", ""),
                "summary": operation.get("summary", "")
            })

    return endpoints
