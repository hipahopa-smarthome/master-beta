import os

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from typing import Optional

app = FastAPI()
templates = Jinja2Templates(directory="templates")


@app.get("/web/login", response_class=HTMLResponse)
async def show_login_form(
        request: Request,
        response_type: str,
        client_id: str,
        redirect_uri: str,
        state: Optional[str] = None,
        scope: Optional[str] = None
):
    return templates.TemplateResponse("login.html", {
        "request": request,
        "client_id": client_id,
        "state": state,
        "scope": scope,
        "response_type": response_type
    })


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8083))

    uvicorn.run(app, host="0.0.0.0", port=port)
