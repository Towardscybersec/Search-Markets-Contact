from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from openpyxl import Workbook
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

import json
import logging
import os
import shutil
from urllib.parse import urlencode
from datetime import datetime
from io import BytesIO
from pathlib import Path

import uvicorn

from auth import (
    authenticate_user,
    clear_session_cookie,
    create_password_reset_token,
    create_session,
    get_client_ip,
    get_csrf_token,
    get_current_user,
    get_current_user_optional,
    hash_password,
    hash_token,
    login_rate_limiter,
    normalize_email,
    normalize_name,
    resolve_csrf_token,
    reset_rate_limiter,
    revoke_user_sessions,
    set_csrf_cookie,
    validate_csrf,
    validate_password_strength,
    issue_session_cookie,
    SESSION_COOKIE_NAME,
)
from database import get_db, init_db
from db_models import PasswordResetToken, Session as DbSessionModel, User
from models import ScrapeResponse
from scraper import scrape_google_maps


app = FastAPI(
    title="Search Markets Contact API",
    description="Extract business/place information from Google Maps search results",
    version="1.0.0",
)

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
OUTPUT_DIR = BASE_DIR / "Output"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("scraper.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

# Shared columns for UI preview and export payload rows.
PLACE_COLUMNS = [
    {"scope": "place", "key": "title", "label": "Company", "type": "text"},
    {"scope": "place", "key": "rating", "label": "Rating", "type": "number"},
    {"scope": "place", "key": "reviews_count", "label": "Reviews", "type": "number"},
    {"scope": "place", "key": "category", "label": "Category", "type": "text"},
    {"scope": "place", "key": "address", "label": "Company Address", "type": "text"},
    {"scope": "place", "key": "phone", "label": "Mobile Number", "type": "text"},
    {"scope": "place", "key": "website", "label": "Website", "type": "url"},
    {"scope": "place", "key": "socials.facebook", "label": "Facebook", "type": "url"},
    {"scope": "place", "key": "socials.instagram", "label": "Instagram", "type": "url"},
    {"scope": "place", "key": "socials.twitter", "label": "Twitter", "type": "url"},
    {"scope": "place", "key": "socials.linkedin", "label": "LinkedIn", "type": "url"},
]


def _nested_get(payload: dict, dotted_key: str, default: object = "") -> object:
    current: object = payload
    for key in dotted_key.split("."):
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def _build_place_row(place: dict) -> list[object]:
    return [_nested_get(place, column["key"], "") for column in PLACE_COLUMNS]

# Configure CORS for credentialed requests.
raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")
allowed_origins = [origin.strip() for origin in raw_origins.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    init_db()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def _render_template(request: Request, template_name: str, context: dict | None = None, status_code: int = 200):
    if context is None:
        context = {}
    csrf_token, needs_cookie = get_csrf_token(request)
    context = {"request": request, "csrf_token": csrf_token, **context}
    response = templates.TemplateResponse(template_name, context, status_code=status_code)
    if needs_cookie:
        set_csrf_cookie(response, csrf_token)
    # Avoid caching authenticated pages and auth forms.
    response.headers["Cache-Control"] = "no-store"
    return response


def _safe_redirect_target(target: str | None) -> str | None:
    if not target:
        return None
    if target.startswith("/") and not target.startswith("//"):
        return target
    return None


def _require_csrf(request: Request, token: str | None = None) -> None:
    validate_csrf(request, resolve_csrf_token(request, token))


def require_user(request: Request, db: DbSession = Depends(get_db)) -> User:
    return get_current_user(request, db)


@app.get("/", response_class=HTMLResponse)
async def root(request: Request, db: DbSession = Depends(get_db)):
    """Serve the web UI."""
    user = get_current_user_optional(request, db)
    auth_mode = request.query_params.get("auth") or request.query_params.get("mode")
    if auth_mode not in ("login", "register"):
        auth_mode = "login"
    context = {"user": user, "auth_mode": auth_mode}
    if not user:
        message = request.query_params.get("message")
        if message:
            context["auth_message"] = message
    return _render_template(request, "index.html", context)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, message: str | None = None, next: str | None = None, db: DbSession = Depends(get_db)):
    user = get_current_user_optional(request, db)
    if user:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    next_url = _safe_redirect_target(next) or "/"
    context = {
        "user": None,
        "auth_mode": "login",
        "auth_message": message,
        "next_url": next_url,
    }
    return _render_template(request, "index.html", context)


@app.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    db: DbSession = Depends(get_db),
    email: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    next_url: str = Form("/", alias="next"),
):
    _require_csrf(request, csrf_token)
    email_key = email.strip().lower()
    safe_next_url = _safe_redirect_target(next_url) or "/"
    if not await login_rate_limiter.allow(f"{get_client_ip(request)}:{email_key}"):
        return _render_template(
            request,
            "index.html",
            {
                "user": None,
                "auth_mode": "login",
                "auth_error": "Too many login attempts. Please wait and try again.",
                "auth_email": email.strip(),
                "next_url": safe_next_url,
            },
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )
    try:
        normalized_email = normalize_email(email)
    except ValueError:
        normalized_email = email_key
    user = authenticate_user(db, normalized_email, password)
    if not user:
        return _render_template(
            request,
            "index.html",
            {
                "user": None,
                "auth_mode": "login",
                "auth_error": "Invalid email or password.",
                "auth_email": email.strip(),
                "next_url": safe_next_url,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    token, expires_at = create_session(db, user, request)
    response = RedirectResponse(url=safe_next_url, status_code=status.HTTP_303_SEE_OTHER)
    issue_session_cookie(response, token, expires_at)
    csrf_value, _ = get_csrf_token(request)
    set_csrf_cookie(response, csrf_value)
    return response


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, db: DbSession = Depends(get_db)):
    user = get_current_user_optional(request, db)
    if user:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    return _render_template(request, "index.html", {"user": None, "auth_mode": "register"})


@app.post("/register", response_class=HTMLResponse)
async def register_submit(
    request: Request,
    db: DbSession = Depends(get_db),
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
):
    _require_csrf(request, csrf_token)
    errors: list[str] = []
    try:
        normalized_name = normalize_name(name)
    except ValueError as exc:
        errors.append(str(exc))
        normalized_name = name.strip()

    try:
        normalized_email = normalize_email(email)
    except ValueError as exc:
        errors.append(str(exc))
        normalized_email = email.strip().lower()

    password_errors = validate_password_strength(password)
    errors.extend(password_errors)

    if errors:
        return _render_template(
            request,
            "index.html",
            {
                "user": None,
                "auth_mode": "register",
                "auth_error": " ".join(errors),
                "auth_name": normalized_name,
                "auth_email": normalized_email,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    user = User(name=normalized_name, email=normalized_email, password_hash=hash_password(password))
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return _render_template(
            request,
            "index.html",
            {
                "user": None,
                "auth_mode": "register",
                "auth_error": "That email is already registered. Please sign in instead.",
                "auth_name": normalized_name,
                "auth_email": normalized_email,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    token, expires_at = create_session(db, user, request)
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    issue_session_cookie(response, token, expires_at)
    csrf_value, _ = get_csrf_token(request)
    set_csrf_cookie(response, csrf_value)
    return response


@app.post("/logout")
async def logout(request: Request, db: DbSession = Depends(get_db), csrf_token: str = Form(...)):
    _require_csrf(request, csrf_token)
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    if raw_token:
        token_hash = hash_token(raw_token)
        session = db.query(DbSessionModel).filter(DbSessionModel.session_token_hash == token_hash).first()
        if session:
            db.delete(session)
            db.commit()
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    clear_session_cookie(response)
    return response


@app.get("/reset", response_class=HTMLResponse)
async def reset_request_page(request: Request, db: DbSession = Depends(get_db)):
    user = get_current_user_optional(request, db)
    if user:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    return _render_template(request, "reset_request.html", {})


@app.post("/reset", response_class=HTMLResponse)
async def reset_request_submit(
    request: Request,
    db: DbSession = Depends(get_db),
    email: str = Form(...),
    csrf_token: str = Form(...),
):
    _require_csrf(request, csrf_token)
    if not await reset_rate_limiter.allow(get_client_ip(request)):
        return _render_template(
            request,
            "reset_request.html",
            {"error": "Too many reset requests. Please wait and try again."},
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    reset_link = None
    try:
        normalized_email = normalize_email(email)
        user = db.query(User).filter(User.email == normalized_email).first()
    except ValueError:
        user = None

    if user:
        token, _expires_at = create_password_reset_token(db, user)
        reset_link = request.url_for("reset_form", token=token)
        # In production, send the reset link via your email provider.
        logger.info("Password reset link for %s: %s", user.email, reset_link)

    show_link = os.getenv("SHOW_RESET_LINK", "false").lower() == "true"
    message = "If an account exists for that email, a reset link has been sent."
    context = {"message": message, "reset_link": str(reset_link) if show_link and reset_link else None}
    return _render_template(request, "reset_request.html", context)


@app.get("/reset/{token}", response_class=HTMLResponse, name="reset_form")
async def reset_form(request: Request, token: str, db: DbSession = Depends(get_db)):
    token_hash = hash_token(token)
    now = datetime.utcnow()
    reset_record = (
        db.query(PasswordResetToken)
        .filter(
            PasswordResetToken.token_hash == token_hash,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
        .first()
    )
    if not reset_record:
        return _render_template(
            request,
            "reset_form.html",
            {"error": "This reset link is invalid or has expired.", "token": token, "valid": False},
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return _render_template(request, "reset_form.html", {"token": token, "valid": True})


@app.post("/reset/{token}", response_class=HTMLResponse)
async def reset_submit(
    request: Request,
    token: str,
    db: DbSession = Depends(get_db),
    password: str = Form(...),
    confirm_password: str = Form(...),
    csrf_token: str = Form(...),
):
    _require_csrf(request, csrf_token)
    if password != confirm_password:
        return _render_template(
            request,
            "reset_form.html",
            {"error": "Passwords do not match.", "token": token, "valid": True},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    errors = validate_password_strength(password)
    if errors:
        return _render_template(
            request,
            "reset_form.html",
            {"error": " ".join(errors), "token": token, "valid": True},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    token_hash = hash_token(token)
    now = datetime.utcnow()
    reset_record = (
        db.query(PasswordResetToken)
        .filter(
            PasswordResetToken.token_hash == token_hash,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
        .first()
    )
    if not reset_record:
        return _render_template(
            request,
            "reset_form.html",
            {"error": "This reset link is invalid or has expired.", "token": token, "valid": False},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    user = reset_record.user
    user.password_hash = hash_password(password)
    reset_record.used_at = now
    db.add(user)
    db.add(reset_record)
    db.commit()

    revoke_user_sessions(db, user.id)
    message = urlencode({"auth": "login", "message": "Password reset successful. Please sign in."})
    return RedirectResponse(url=f"/?{message}", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "ok",
        "message": "SearchMarkets Contact API is running",
        "endpoints": {
            "scrape": "/api/scrape?query=<search-term>",
            "results": "/api/results?query=<search-term>",
        },
    }


def _safe_query_name(query: str) -> str:
    return "".join(c if c.isalnum() or c in (" ", "_", "-") else "_" for c in query).strip()


def _get_output_dir(query: str) -> Path:
    return OUTPUT_DIR / _safe_query_name(query)


def _resolve_output_folder(folder_name: str) -> Path:
    if not folder_name:
        raise HTTPException(status_code=400, detail="Folder name cannot be empty")

    candidate = (OUTPUT_DIR / folder_name).resolve()
    if OUTPUT_DIR.resolve() not in candidate.parents and candidate != OUTPUT_DIR.resolve():
        raise HTTPException(status_code=400, detail="Invalid folder path")

    if not candidate.exists() or not candidate.is_dir():
        raise HTTPException(status_code=404, detail="Folder not found")

    return candidate


def _get_latest_response_file(output_dir: Path) -> tuple[Path | None, bool]:
    final_file = output_dir / "response_final.json"
    if final_file.exists():
        return final_file, True

    response_files = sorted(output_dir.glob("response*.json"))
    if not response_files:
        return None, False
    return response_files[-1], False


def _get_scrape_iterations() -> int:
    raw_value = os.getenv("SCRAPE_ITERATIONS", "10")
    try:
        iterations = int(raw_value)
    except ValueError:
        logger.warning("Invalid SCRAPE_ITERATIONS=%s; defaulting to 10", raw_value)
        return 10
    return max(1, iterations)


@app.get("/api/results")
async def get_results(
    query: str = Query(..., description="Search Contacts used."),
    user: User = Depends(require_user),
):
    """Fetch the latest stored results for a query."""
    if not query or len(query.strip()) == 0:
        raise HTTPException(status_code=400, detail="Query parameter cannot be empty")

    output_dir = _get_output_dir(query)
    response_file, is_final = _get_latest_response_file(output_dir)
    if response_file is None or not response_file.exists():
        raise HTTPException(status_code=404, detail="No results found yet")

    with open(response_file, "r", encoding="utf-8") as f:
        payload = json.load(f)

    updated_at = datetime.fromtimestamp(response_file.stat().st_mtime).isoformat()

    return {
        "is_final": is_final,
        "file": response_file.name,
        "updated_at": updated_at,
        "columns": PLACE_COLUMNS,
        "data": payload,
    }


@app.get("/api/output")
async def list_output_folders(user: User = Depends(require_user)):
    """List available output folders and summary information."""
    if not OUTPUT_DIR.exists():
        return {"folders": []}

    folders = []
    for folder in sorted([f for f in OUTPUT_DIR.iterdir() if f.is_dir()], key=lambda x: x.name.lower()):
        response_files = sorted(folder.glob("response*.json"))
        final_exists = (folder / "response_final.json").exists()
        latest_mtime = max((f.stat().st_mtime for f in response_files), default=folder.stat().st_mtime)
        folders.append(
            {
                "name": folder.name,
                "file_count": len(response_files),
                "has_final": final_exists,
                "last_updated": datetime.fromtimestamp(latest_mtime).isoformat(),
            }
        )

    return {"folders": folders}


@app.delete("/api/output/delete")
async def delete_output_folder(
    request: Request,
    folder: str = Query(..., description="Output folder name"),
    user: User = Depends(require_user),
):
    """Delete an output folder and all of its response files."""
    _require_csrf(request)
    folder_path = _resolve_output_folder(folder)
    response_files = list(folder_path.glob("response*.json"))
    try:
        shutil.rmtree(folder_path)
    except Exception as exc:
        logger.error("Failed to delete output folder %s: %s", folder_path, exc)
        raise HTTPException(status_code=500, detail="Unable to delete output folder")
    return {
        "deleted": folder_path.name,
        "file_count": len(response_files),
        "message": f'Deleted "{folder_path.name}".',
    }


@app.get("/api/output/files")
async def list_output_files(
    folder: str = Query(..., description="Output folder name"),
    user: User = Depends(require_user),
):
    """List response files inside a given output folder."""
    folder_path = _resolve_output_folder(folder)
    response_files = sorted(folder_path.glob("response*.json"), key=lambda x: x.name)

    files = []
    for file_path in response_files:
        files.append(
            {
                "name": file_path.name,
                "is_final": file_path.name == "response_final.json",
                "last_updated": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
            }
        )

    return {"folder": folder_path.name, "files": files}


@app.get("/api/output/results")
async def get_output_results(
    folder: str = Query(..., description="Output folder name"),
    file: str = Query(..., description="Response file name"),
    user: User = Depends(require_user),
):
    """Return parsed contents of a response file within an output folder."""
    folder_path = _resolve_output_folder(folder)
    file_path = (folder_path / file).resolve()
    if folder_path.resolve() not in file_path.parents:
        raise HTTPException(status_code=400, detail="Invalid file path")

    if not file_path.exists() or file_path.suffix.lower() != ".json":
        raise HTTPException(status_code=404, detail="Response file not found")

    with open(file_path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    return {
        "folder": folder_path.name,
        "file": file_path.name,
        "updated_at": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
        "columns": PLACE_COLUMNS,
        "data": payload,
    }


@app.get("/api/output/export")
async def export_output_folder(
    request: Request,
    folder: str = Query(..., description="Output folder name"),
    user: User = Depends(require_user),
):
    """Export all scraped places from a folder as an Excel file."""
    _require_csrf(request)
    folder_path = _resolve_output_folder(folder)
    response_files = sorted(folder_path.glob("response*.json"), key=lambda x: x.name)
    if not response_files:
        raise HTTPException(status_code=404, detail="No response files found for export")

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Scraped Places"
    sheet.append([column["label"] for column in PLACE_COLUMNS])

    for file_path in response_files:
        with open(file_path, "r", encoding="utf-8") as f:
            payload = json.load(f)

        places = payload.get("places", [])
        for place in places:
            place_payload = place if isinstance(place, dict) else {}
            sheet.append(_build_place_row(place_payload))

    output_stream = BytesIO()
    workbook.save(output_stream)
    output_stream.seek(0)

    filename = f"{folder_path.name.replace(' ', '_')}_scraped_data.xlsx"
    headers = {"Content-Disposition": f"attachment; filename=\"{filename}\""}
    return StreamingResponse(
        output_stream,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers=headers,
    )


@app.get("/api/scrape", response_model=ScrapeResponse)
async def scrape_places(
    request: Request,
    query: str = Query(..., description="Search query for Google Maps (e.g., 'restaurants in NYC')"),
    user: User = Depends(require_user),
):
    """
    Scrape Google Maps for business/place information

    Runs SCRAPE_ITERATIONS scraping iterations, saves each to responseN.json, then creates response_final.json with unique results.

    Example: /api/scrape?query=restaurants+in+NYC

    Returns:
        JSON with scraped places including title, rating, reviews, category, address, phone, website, socials
    """
    _require_csrf(request)
    if not query or len(query.strip()) == 0:
        raise HTTPException(status_code=400, detail="Query parameter cannot be empty")

    try:
        # Create output directory for this query
        output_dir = _get_output_dir(query)
        output_dir.mkdir(parents=True, exist_ok=True)

        iterations = _get_scrape_iterations()
        logger.info("Starting %s scraping iterations for query: '%s'", iterations, query)
        logger.info("Output directory: %s", output_dir)

        all_responses = []

        # Run scraping 10 times
        for iteration in range(1, iterations + 1):
            logger.info("=== Starting iteration %s/%s ===", iteration, iterations)

            try:
                # Perform scraping
                places = scrape_google_maps(query)

                # Build response
                response = ScrapeResponse(query=query, total_results=len(places), places=places)

                # Save to responseN.json
                response_file = output_dir / f"response{iteration}.json"
                with open(response_file, "w", encoding="utf-8") as f:
                    json.dump(response.model_dump(), f, indent=4, ensure_ascii=False)

                logger.info("Iteration %s: Found %s places", iteration, len(places))
                logger.info("Saved to: %s", response_file)

                all_responses.append(response)

            except Exception as e:
                logger.error("Error in iteration %s: %s", iteration, e)
                continue

        # Create response_final.json with unique places
        logger.info("Creating response_final.json with unique results...")

        # Collect all places from all iterations
        all_places = []
        for response in all_responses:
            all_places.extend(response.places)

        logger.info("Total places from all iterations: %s", len(all_places))

        # Find unique places (by title + address combination)
        unique_places: dict[str, object] = {}
        for place in all_places:
            # Create a unique key based on title and address
            key = f"{place.title}|{place.address}"

            if key not in unique_places:
                unique_places[key] = place
            else:
                # If place exists, merge data (fill in missing fields)
                existing = unique_places[key]
                if not existing.rating and place.rating:
                    existing.rating = place.rating
                if not existing.reviews_count and place.reviews_count:
                    existing.reviews_count = place.reviews_count
                if not existing.category and place.category:
                    existing.category = place.category
                if not existing.phone and place.phone:
                    existing.phone = place.phone
                if not existing.website and place.website:
                    existing.website = place.website
                if place.socials:
                    if not existing.socials.facebook and place.socials.facebook:
                        existing.socials.facebook = place.socials.facebook
                    if not existing.socials.instagram and place.socials.instagram:
                        existing.socials.instagram = place.socials.instagram
                    if not existing.socials.twitter and place.socials.twitter:
                        existing.socials.twitter = place.socials.twitter
                    if not existing.socials.linkedin and place.socials.linkedin:
                        existing.socials.linkedin = place.socials.linkedin

        unique_places_list = list(unique_places.values())
        logger.info("Unique places after deduplication: %s", len(unique_places_list))

        # Create final response
        final_response = ScrapeResponse(query=query, total_results=len(unique_places_list), places=unique_places_list)

        # Save response_final.json
        final_file = output_dir / "response_final.json"
        with open(final_file, "w", encoding="utf-8") as f:
            json.dump(final_response.model_dump(), f, indent=4, ensure_ascii=False)

        logger.info("Final response saved to: %s", final_file)
        logger.info("=== Scraping complete for query: '%s' ===", query)

        return final_response

    except Exception as e:
        logger.error("Scraping failed: %s", str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scraping failed: {str(e)}")


if __name__ == "__main__":
    print(" Starting SearchMarkets Contact API on http://localhost:3000")
    print(" API docs available at http://localhost:3000/docs")
    print("\nExample usage:")
    print('  curl "http://localhost:3000/api/scrape?query=restaurants+in+NYC"')

    uvicorn.run(app, host="0.0.0.0", port=3000)
