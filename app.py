from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session
)

from collections import defaultdict, deque
import threading
import time

import uuid
import bcrypt
import os
import secrets
import hmac

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from decimal import Decimal, InvalidOperation

from config import initialize_database
from admin import admin_bp


# =====================================================
# FLASK APPLICATION
# =====================================================

app = Flask(__name__)


# =====================================================
# GLOBAL WEB RATE LIMITER
# =====================================================

GLOBAL_RATE_LIMIT = 100
GLOBAL_RATE_WINDOW = 1.0

_rate_limit_store = defaultdict(deque)
_rate_limit_lock = threading.Lock()


def get_client_ip():
    """
    Get the client's IP address.

    Do NOT blindly trust X-Forwarded-For unless your
    deployment proxy is configured to sanitize it.
    """

    return request.remote_addr or "unknown"


def is_rate_limited(client_ip):
    """
    Returns True when the client has exceeded the
    global request limit within the current window.
    """

    current_time = time.monotonic()

    with _rate_limit_lock:

        request_times = _rate_limit_store[client_ip]

        # Remove requests outside the current window.
        while (
            request_times
            and
            current_time - request_times[0]
            >= GLOBAL_RATE_WINDOW
        ):
            request_times.popleft()

        # Check limit BEFORE adding the new request.
        if len(request_times) >= GLOBAL_RATE_LIMIT:
            return True

        request_times.append(current_time)

        return False


def cleanup_rate_limit_store():
    """
    Remove IP entries that have not made a request
    during the current rate-limit window.
    """

    current_time = time.monotonic()

    with _rate_limit_lock:

        expired_ips = []

        for client_ip, request_times in _rate_limit_store.items():

            while (
                request_times
                and
                current_time - request_times[0]
                >= GLOBAL_RATE_WINDOW
            ):
                request_times.popleft()

            if not request_times:
                expired_ips.append(client_ip)

        for client_ip in expired_ips:
            _rate_limit_store.pop(client_ip, None)


# =====================================================
# GLOBAL RATE LIMIT CHECK
# =====================================================

@app.before_request
def global_rate_limit():

    client_ip = get_client_ip()

    if is_rate_limited(client_ip):

        response = (
            "Too Many Requests",
            429,
            {
                "Retry-After": "1"
            }
        )

        return response


# =====================================================
# RATE LIMIT STORE CLEANUP
# =====================================================

def rate_limit_cleanup_loop():

    while True:

        time.sleep(60)

        cleanup_rate_limit_store()


cleanup_thread = threading.Thread(
    target=rate_limit_cleanup_loop,
    daemon=True
)

cleanup_thread.start()



# =====================================================
# SECRET KEY
# =====================================================

app.secret_key = os.environ["FLASK_SECRET_KEY"]



CSRF_SESSION_KEY = "csrf_token"


def get_csrf_token():

    if CSRF_SESSION_KEY not in session:

        session[CSRF_SESSION_KEY] = (
            secrets.token_urlsafe(32)
        )

    return session[CSRF_SESSION_KEY]

@app.context_processor
def csrf_context():

    return {
        "csrf_token": get_csrf_token
    }


@app.before_request
def global_csrf_protection():

    method = request.method.upper()

    if method in (
        "GET",
        "HEAD",
        "OPTIONS",
        "TRACE"
    ):
        return None


    submitted_token = request.form.get(
        "csrf_token",
        ""
    )

    session_token = session.get(
        CSRF_SESSION_KEY
    )


    if (
        not session_token
        or not submitted_token
        or not hmac.compare_digest(
            submitted_token,
            session_token
        )
    ):

        return (
            "CSRF validation failed",
            403
        )


    return None




app.register_blueprint(admin_bp)

# =====================================================
# DATABASE INITIALIZATION
# =====================================================

db_engine = initialize_database()


# =====================================================
# LOGIN / HOME PAGE
# =====================================================

@app.route("/", methods=["GET", "POST"])
def home():

    try:

        # -------------------------------------------------
        # SHOW LOGIN PAGE
        # -------------------------------------------------

        if request.method == "GET":

            return render_template("login.html")


        # -------------------------------------------------
        # COLLECT LOGIN INPUTS AS STRINGS
        # -------------------------------------------------

        username = str(
            request.form.get("username", "")
        )

        password = str(
            request.form.get("password", "")
        )


        # -------------------------------------------------
        # REMOVE OUTER SPACES
        # -------------------------------------------------

        username = username.strip()
        password = password.strip()


        # -------------------------------------------------
        # CHECK EMPTY VALUES
        # -------------------------------------------------

        if not username or not password:

            flash(
                "Invalid user credentials",
                "error"
            )

            return redirect(
                url_for("home")
            )


        # -------------------------------------------------
        # FIND USER BY USERNAME
        # -------------------------------------------------

        with db_engine.connect() as connection:

            user = connection.execute(

                text(
                    """
                    SELECT
                        uuid,
                        username,
                        password,
                        status
                    FROM lpusers
                    WHERE username = :username
                    LIMIT 1
                    """
                ),

                {
                    "username": username
                }

            ).mappings().first()


        # -------------------------------------------------
        # USER DOES NOT EXIST
        # -------------------------------------------------

        if not user:

            flash(
                "Invalid user credentials",
                "error"
            )

            return redirect(
                url_for("home")
            )


        # -------------------------------------------------
        # CHECK USER STATUS
        # -------------------------------------------------

        if not user["status"]:

            flash(
                "Invalid user credentials",
                "error"
            )

            return redirect(
                url_for("home")
            )


        # -------------------------------------------------
        # BCRYPT PASSWORD VERIFICATION
        # -------------------------------------------------

        password_matches = bcrypt.checkpw(

            password.encode("utf-8"),

            user["password"].encode("utf-8")

        )


        # -------------------------------------------------
        # PASSWORD DOES NOT MATCH
        # -------------------------------------------------

        if not password_matches:

            flash(
                "Invalid user credentials",
                "error"
            )

            return redirect(
                url_for("home")
            )


        # -------------------------------------------------
        # CREATE USER SESSION
        # -------------------------------------------------

        session["user_uuid"] = user["uuid"]

        session["username"] = user["username"]


        # -------------------------------------------------
        # LOGIN SUCCESSFUL
        # -------------------------------------------------

        return redirect(
            url_for("userselpage")
        )


    except Exception:

        flash(
            "Something went wrong. Please try again.",
            "error"
        )

        return redirect(
            url_for("home")
        )

# =====================================================
# CREATE ACCOUNT
# =====================================================

@app.route("/create-account", methods=["GET", "POST"])
def create_account():

    try:

        if request.method == "GET":

            return render_template("create_account.html")


        # -------------------------------------------------
        # COLLECT INPUTS
        # -------------------------------------------------

        username = str(
            request.form.get("username", "")
        )

        phone_number = str(
            request.form.get("phone_number", "")
        )

        password = str(
            request.form.get("password", "")
        )


        username = username.strip()
        phone_number = phone_number.strip()
        password = password.strip()


        # -------------------------------------------------
        # CHECK ALL FIELDS
        # -------------------------------------------------

        if not username or not phone_number or not password:

            flash(
                "Please fill all your details first",
                "error"
            )

            return redirect(
                url_for("create_account")
            )


        # -------------------------------------------------
        # USERNAME CANNOT CONTAIN SPACE
        # -------------------------------------------------

        if " " in username:

            flash(
                "Username cannot contain spaces",
                "error"
            )

            return redirect(
                url_for("create_account")
            )


        # -------------------------------------------------
        # PHONE NUMBER - NUMBERS ONLY
        # -------------------------------------------------

        if not phone_number.isdigit():

            flash(
                "Phone number must contain numbers only",
                "error"
            )

            return redirect(
                url_for("create_account")
            )


        # -------------------------------------------------
        # PASSWORD MAXIMUM LENGTH
        # -------------------------------------------------

        if len(password) > 20:

            flash(
                "Password cannot be more than 20 characters",
                "error"
            )

            return redirect(
                url_for("create_account")
            )


        # -------------------------------------------------
        # CHECK USERNAME
        # -------------------------------------------------

        with db_engine.connect() as connection:

            existing_user = connection.execute(

                text(
                    """
                    SELECT uuid
                    FROM lpusers
                    WHERE username = :username
                    LIMIT 1
                    """
                ),

                {
                    "username": username
                }

            ).fetchone()


        if existing_user:

            flash(
                "Username not allowed",
                "error"
            )

            return redirect(
                url_for("create_account")
            )


        # -------------------------------------------------
        # HASH PASSWORD
        # -------------------------------------------------

        password_hash = bcrypt.hashpw(

            password.encode("utf-8"),

            bcrypt.gensalt()

        ).decode("utf-8")


        # -------------------------------------------------
        # GENERATE UUID
        # -------------------------------------------------

        user_uuid = str(
            uuid.uuid4()
        )


        # -------------------------------------------------
        # INSERT USER
        # -------------------------------------------------

        with db_engine.connect() as connection:

            connection.execute(

                text(
                    """
                    INSERT INTO lpusers
                    (
                        uuid,
                        username,
                        phone_number,
                        password
                    )

                    VALUES
                    (
                        :uuid,
                        :username,
                        :phone_number,
                        :password
                    )
                    """
                ),

                {
                    "uuid": user_uuid,
                    "username": username,
                    "phone_number": phone_number,
                    "password": password_hash
                }

            )

            connection.commit()


        # -------------------------------------------------
        # SUCCESS
        # -------------------------------------------------

        flash(
            "Account created successfully",
            "success"
        )


        return redirect(
            url_for("create_account")
        )


    except Exception:

        flash(
            "Something went wrong. Please try again.",
            "error"
        )

        return redirect(
            url_for("create_account")
        )

# =====================================================
# USER SELECTION PAGE
# =====================================================

@app.route("/userselpage")
def userselpage():

    try:

        # -------------------------------------------------
        # CHECK LOGIN SESSION
        # -------------------------------------------------

        if not session.get("user_uuid"):

            return redirect(
                url_for("home")
            )


        # -------------------------------------------------
        # FETCH ADMIN CONTACT
        # -------------------------------------------------

        with db_engine.connect() as connection:

            admin_details = connection.execute(
                text(
                    """
                    SELECT
                        contact
                    FROM adetails
                    LIMIT 1
                    """
                )
            ).mappings().first()


        admin_contact = "Not Added"

        if admin_details:

            admin_contact = admin_details["contact"]


        # -------------------------------------------------
        # USER SELECTION PAGE
        # -------------------------------------------------

        return render_template(
            "usersel.html",
            admin_contact=admin_contact
        )


    except Exception:

        flash(
            "Something went wrong. Please try again.",
            "error"
        )

        return redirect(
            url_for("home")
        )


@app.route("/udashboard")
def udashboard():

    try:

        # -------------------------------------------------
        # CHECK LOGIN SESSION
        # -------------------------------------------------

        if not session.get("user_uuid"):

            return redirect(
                url_for("home")
            )


        user_uuid = session.get("user_uuid")


        # -------------------------------------------------
        # FETCH USER + MATCH DATA
        # -------------------------------------------------

        with db_engine.connect() as connection:

            # ---------------------------------------------
            # USER BALANCE
            # ---------------------------------------------

            user = connection.execute(

                text(
                    """
                    SELECT
                        money
                    FROM lpusers
                    WHERE uuid = :user_uuid
                    LIMIT 1
                    """
                ),

                {
                    "user_uuid": user_uuid
                }

            ).mappings().first()


            # ---------------------------------------------
            # USER NOT FOUND
            # ---------------------------------------------

            if not user:

                session.clear()

                return redirect(
                    url_for("home")
                )


            # ---------------------------------------------
            # AVAILABLE MATCHES
            # ---------------------------------------------

            matches = connection.execute(

                text(
                    """
                    SELECT
                        uuid,
                        amount,
                        timestamp
                    FROM umatches
                    WHERE
                        match_initiated_by != :user_uuid
                        AND status = 'active'
                        AND is_terminated = 0
                    ORDER BY timestamp DESC
                    """
                ),

                {
                    "user_uuid": user_uuid
                }

            ).mappings().all()


            # ---------------------------------------------
            # ONGOING MATCH
            # ---------------------------------------------

            ongoing_match = connection.execute(

                text(
                    """
                    SELECT
                        uuid,
                        match_initiated_by,
                        match_attendedby,
                        amount,
                        roomcode,
                        timestamp,
                        atimestamp
                    FROM umatches
                    WHERE
                        (
                            match_initiated_by = :user_uuid
                            OR match_attendedby = :user_uuid
                        )
                        AND status = 'ongoing'
                        AND is_terminated = 0
                    ORDER BY atimestamp DESC
                    LIMIT 1
                    """
                ),

                {
                    "user_uuid": user_uuid
                }

            ).mappings().first()


            # ---------------------------------------------
            # ADMIN CONTACT
            # ---------------------------------------------

            admin_details = connection.execute(

                text(
                    """
                    SELECT
                        contact
                    FROM adetails
                    LIMIT 1
                    """
                )

            ).mappings().first()


            # ---------------------------------------------
            # CHECK WHETHER CURRENT USER ALREADY
            # SUBMITTED RESULT FOR THIS MATCH
            # ---------------------------------------------

            result_submitted = False

            if ongoing_match:

                result = connection.execute(

                    text(
                        """
                        SELECT
                            matchuuid,
                            user1uuid,
                            user1option,
                            user2uuid,
                            user2option
                        FROM uresults
                        WHERE matchuuid = :match_uuid
                        LIMIT 1
                        """
                    ),

                    {
                        "match_uuid": ongoing_match["uuid"]
                    }

                ).mappings().first()


                if result:

                    if (
                        result["user1uuid"] == user_uuid
                        and result["user1option"] is not None
                    ):

                        result_submitted = True


                    elif (
                        result["user2uuid"] == user_uuid
                        and result["user2option"] is not None
                    ):

                        result_submitted = True


        # -------------------------------------------------
        # ADMIN CONTACT VALUE
        # -------------------------------------------------

        admin_contact = "Not Added"

        if admin_details:

            admin_contact = admin_details["contact"]


        # -------------------------------------------------
        # RENDER DASHBOARD
        # -------------------------------------------------

        return render_template(

            "udashboard.html",

            money=user["money"],

            matches=matches,

            ongoing_match=ongoing_match,

            admin_contact=admin_contact,

            result_submitted=result_submitted

        )


    except Exception:

        flash(
            "Something went wrong. Please try again.",
            "error"
        )

        return redirect(
            url_for("home")
        )

# =====================================================
# SUBMIT RESULT
# =====================================================
@app.route("/submit-result", methods=["POST"])
def submit_result():

    try:

        # -------------------------------------------------
        # CHECK LOGIN
        # -------------------------------------------------

        if not session.get("user_uuid"):

            return redirect(
                url_for("home")
            )


        user_uuid = session.get("user_uuid")


        # -------------------------------------------------
        # COLLECT INPUTS AS STRINGS
        # -------------------------------------------------

        match_uuid = str(
            request.form.get("match_uuid", "")
        ).strip()


        selected_result = str(
            request.form.get("result", "")
        ).strip().lower()


        # -------------------------------------------------
        # VALIDATE RESULT
        # -------------------------------------------------

        if selected_result not in ["win", "loss"]:

            flash(
                "Please select your result",
                "error"
            )

            return redirect(
                url_for("udashboard")
            )


        if not match_uuid:

            flash(
                "Invalid match",
                "error"
            )

            return redirect(
                url_for("udashboard")
            )


        # -------------------------------------------------
        # PROCESS RESULT
        # -------------------------------------------------

        with db_engine.begin() as connection:

            # ---------------------------------------------
            # GET ONGOING MATCH
            # ---------------------------------------------

            match = connection.execute(

                text(
                    """
                    SELECT
                        uuid,
                        match_initiated_by,
                        match_attendedby,
                        status,
                        is_terminated
                    FROM umatches
                    WHERE
                        uuid = :match_uuid
                    LIMIT 1
                    FOR UPDATE
                    """
                ),

                {
                    "match_uuid": match_uuid
                }

            ).mappings().first()


            # ---------------------------------------------
            # MATCH VALIDATION
            # ---------------------------------------------

            if not match:

                flash(
                    "Match not found",
                    "error"
                )

                return redirect(
                    url_for("udashboard")
                )


            if (
                match["status"] != "ongoing"
                or match["is_terminated"]
            ):

                flash(
                    "Match is not ongoing",
                    "error"
                )

                return redirect(
                    url_for("udashboard")
                )


            # ---------------------------------------------
            # CHECK USER IS ACTUALLY IN THIS MATCH
            # ---------------------------------------------

            if (
                match["match_initiated_by"] != user_uuid
                and match["match_attendedby"] != user_uuid
            ):

                flash(
                    "Invalid match",
                    "error"
                )

                return redirect(
                    url_for("udashboard")
                )


            # ---------------------------------------------
            # CHECK EXISTING RESULT
            # ---------------------------------------------

            existing_result = connection.execute(

                text(
                    """
                    SELECT
                        matchuuid,
                        user1uuid,
                        user1option,
                        user2uuid,
                        user2option
                    FROM uresults
                    WHERE matchuuid = :match_uuid
                    LIMIT 1
                    FOR UPDATE
                    """
                ),

                {
                    "match_uuid": match_uuid
                }

            ).mappings().first()


            # ---------------------------------------------
            # FIRST USER TO SUBMIT
            # ---------------------------------------------

            if not existing_result:

                connection.execute(

                    text(
                        """
                        INSERT INTO uresults
                        (
                            matchuuid,
                            user1uuid,
                            user1option,
                            status
                        )

                        VALUES
                        (
                            :matchuuid,
                            :user1uuid,
                            :user1option,
                            'hold'
                        )
                        """
                    ),

                    {
                        "matchuuid": match_uuid,

                        "user1uuid": user_uuid,

                        "user1option": selected_result

                    }

                )


            else:

                # -----------------------------------------
                # USER 1
                # -----------------------------------------

                if (
                    existing_result["user1uuid"]
                    == user_uuid
                ):

                    if existing_result["user1option"]:

                        flash(
                            "Result already submitted",
                            "error"
                        )

                        return redirect(
                            url_for("udashboard")
                        )


                    connection.execute(

                        text(
                            """
                            UPDATE uresults

                            SET user1option = :option

                            WHERE matchuuid = :match_uuid
                            """
                        ),

                        {
                            "option": selected_result,

                            "match_uuid": match_uuid

                        }

                    )


                # -----------------------------------------
                # USER 2
                # -----------------------------------------

                elif (
                    existing_result["user2uuid"]
                    == user_uuid
                ):

                    if existing_result["user2option"]:

                        flash(
                            "Result already submitted",
                            "error"
                        )

                        return redirect(
                            url_for("udashboard")
                        )


                    connection.execute(

                        text(
                            """
                            UPDATE uresults

                            SET user2option = :option

                            WHERE matchuuid = :match_uuid
                            """
                        ),

                        {
                            "option": selected_result,

                            "match_uuid": match_uuid

                        }

                    )


                # -----------------------------------------
                # USER 2 HAS NOT BEEN REGISTERED YET
                # -----------------------------------------

                else:

                    connection.execute(

                        text(
                            """
                            UPDATE uresults

                            SET
                                user2uuid = :user2uuid,
                                user2option = :user2option

                            WHERE matchuuid = :match_uuid
                            """
                        ),

                        {
                            "user2uuid": user_uuid,

                            "user2option": selected_result,

                            "match_uuid": match_uuid

                        }

                    )


        # -------------------------------------------------
        # SUCCESS POPUP
        # -------------------------------------------------

        session["result_submitted"] = True


        return redirect(
            url_for("udashboard")
        )


    except Exception:

        flash(
            "Something went wrong. Please try again.",
            "error"
        )

        return redirect(
            url_for("udashboard")
        )


# =====================================================
# CLEAR RESULT SUBMISSION POPUP
# =====================================================
@app.route("/clear-result-submitted", methods=["POST"])
def clear_result_submitted():

    try:

        session.pop(
            "result_submitted",
            None
        )

        return "", 204


    except Exception:

        return "", 204


# =====================================================
# START MATCH
# =====================================================

@app.route("/start-match", methods=["POST"])
def start_match():

    try:

        # -------------------------------------------------
        # CHECK LOGIN SESSION
        # -------------------------------------------------

        if not session.get("user_uuid"):

            return redirect(
                url_for("home")
            )


        user_uuid = session.get("user_uuid")


        # -------------------------------------------------
        # COLLECT INPUTS AS STRINGS
        # -------------------------------------------------

        amount_input = str(
            request.form.get("amount", "")
        )

        roomcode = str(
            request.form.get("roomcode", "")
        )


        # -------------------------------------------------
        # REMOVE OUTER SPACES
        # -------------------------------------------------

        amount_input = amount_input.strip()
        roomcode = roomcode.strip()


        # -------------------------------------------------
        # CHECK EMPTY VALUES
        # -------------------------------------------------

        if not amount_input or not roomcode:

            flash(
                "Please fill all your details first",
                "error"
            )

            return redirect(
                url_for("udashboard")
            )


        # -------------------------------------------------
        # AMOUNT MUST BE AN INTEGER
        # -------------------------------------------------

        try:

            amount = int(amount_input)

        except ValueError:

            flash(
                "Invalid amount",
                "error"
            )

            return redirect(
                url_for("udashboard")
            )


        # -------------------------------------------------
        # MINIMUM AMOUNT
        # -------------------------------------------------

        if amount < 50:

            flash(
                "Minimum amount is 50",
                "error"
            )

            return redirect(
                url_for("udashboard")
            )


        # -------------------------------------------------
        # MAXIMUM AMOUNT
        # -------------------------------------------------

        if amount > 50000000:

            flash(
                "Maximum amount is 50000000",
                "error"
            )

            return redirect(
                url_for("udashboard")
            )


        # -------------------------------------------------
        # AMOUNT MUST BE IN MULTIPLES OF 50
        # -------------------------------------------------

        if amount % 50 != 0:

            flash(
                "Amount must be in multiples of 50",
                "error"
            )

            return redirect(
                url_for("udashboard")
            )


        # -------------------------------------------------
        # CHECK USER + BALANCE + EXISTING MATCH
        # -------------------------------------------------

        with db_engine.connect() as connection:

            user = connection.execute(

                text(
                    """
                    SELECT
                        money
                    FROM lpusers
                    WHERE uuid = :user_uuid
                    LIMIT 1
                    """
                ),

                {
                    "user_uuid": user_uuid
                }

            ).mappings().first()


            # -------------------------------------------------
            # USER NOT FOUND
            # -------------------------------------------------

            if not user:

                session.clear()

                return redirect(
                    url_for("home")
                )


            # -------------------------------------------------
            # CHECK INSUFFICIENT MONEY
            # -------------------------------------------------

            if amount > user["money"]:

                flash(
                    "insufficient money",
                    "error"
                )

                return redirect(
                    url_for("udashboard")
                )


            # -------------------------------------------------
            # CHECK EXISTING ACTIVE / ONGOING MATCH
            # -------------------------------------------------

            existing_match = connection.execute(

                text(
                    """
                    SELECT uuid
                    FROM umatches
                    WHERE
                        (
                            match_initiated_by = :user_uuid
                            OR match_attendedby = :user_uuid
                        )
                        AND is_terminated = 0
                        AND status IN ('active', 'ongoing')
                    LIMIT 1
                    """
                ),

                {
                    "user_uuid": user_uuid
                }

            ).first()


            if existing_match:

                flash(
                    "match initiated already",
                    "error"
                )

                return redirect(
                    url_for("udashboard")
                )


        # -------------------------------------------------
        # CREATE MATCH UUID
        # -------------------------------------------------

        match_uuid = str(
            uuid.uuid4()
        )


        # -------------------------------------------------
        # INSERT MATCH
        # -------------------------------------------------

        try:

            with db_engine.connect() as connection:

                connection.execute(

                    text(
                        """
                        INSERT INTO umatches
                        (
                            uuid,
                            match_initiated_by,
                            amount,
                            roomcode
                        )

                        VALUES
                        (
                            :uuid,
                            :match_initiated_by,
                            :amount,
                            :roomcode
                        )
                        """
                    ),

                    {
                        "uuid": match_uuid,
                        "match_initiated_by": user_uuid,
                        "amount": amount,
                        "roomcode": roomcode
                    }

                )

                connection.commit()


        except IntegrityError:

            flash(
                "Room code already exists",
                "error"
            )

            return redirect(
                url_for("udashboard")
            )


        # -------------------------------------------------
        # SUCCESS
        # -------------------------------------------------

        flash(
            "Match started successfully",
            "success"
        )


        return redirect(
            url_for("udashboard")
        )


    except Exception:

        flash(
            "Something went wrong. Please try again.",
            "error"
        )

        return redirect(
            url_for("udashboard")
        )

# =====================================================
# JOIN MATCH
# =====================================================

@app.route("/join-match", methods=["POST"])
def join_match():

    # -------------------------------------------------
    # CHECK LOGIN
    # -------------------------------------------------

    if not session.get("user_uuid"):

        return redirect(
            url_for("home")
        )


    user_uuid = session.get("user_uuid")


    # -------------------------------------------------
    # COLLECT MATCH UUID
    # -------------------------------------------------

    match_uuid = str(
        request.form.get("match_uuid", "")
    ).strip()


    if not match_uuid:

        flash(
            "Invalid match",
            "error"
        )

        return redirect(
            url_for("udashboard")
        )


    # -------------------------------------------------
    # START DATABASE TRANSACTION
    # -------------------------------------------------

    try:

        with db_engine.begin() as connection:

            # -----------------------------------------
            # LOCK THE USER ROW
            # -----------------------------------------

            user = connection.execute(

                text(
                    """
                    SELECT
                        uuid,
                        money
                    FROM lpusers
                    WHERE uuid = :user_uuid
                    LIMIT 1
                    FOR UPDATE
                    """
                ),

                {
                    "user_uuid": user_uuid
                }

            ).mappings().first()


            if not user:

                session.clear()

                return redirect(
                    url_for("home")
                )


            # -----------------------------------------
            # GET SELECTED MATCH
            # LOCK MATCH ROW
            # -----------------------------------------

            match = connection.execute(

                text(
                    """
                    SELECT
                        uuid,
                        match_initiated_by,
                        amount,
                        roomcode,
                        status,
                        is_terminated,
                        match_attendedby
                    FROM umatches
                    WHERE uuid = :match_uuid
                    LIMIT 1
                    FOR UPDATE
                    """
                ),

                {
                    "match_uuid": match_uuid
                }

            ).mappings().first()


            # -----------------------------------------
            # MATCH DOES NOT EXIST
            # -----------------------------------------

            if not match:

                flash(
                    "Match not available",
                    "error"
                )

                return redirect(
                    url_for("udashboard")
                )


            # -----------------------------------------
            # USER CANNOT PLAY HIS OWN MATCH
            # -----------------------------------------

            if match["match_initiated_by"] == user_uuid:

                flash(
                    "You cannot play your own match",
                    "error"
                )

                return redirect(
                    url_for("udashboard")
                )


            # -----------------------------------------
            # MATCH MUST BE ACTIVE
            # -----------------------------------------

            if (
                match["status"] != "active"
                or match["is_terminated"]
                or match["match_attendedby"] is not None
            ):

                flash(
                    "Match is no longer available",
                    "error"
                )

                return redirect(
                    url_for("udashboard")
                )


            # -----------------------------------------
            # CHECK USER'S ONGOING MATCH
            #
            # Active matches are allowed.
            # Ongoing matches are NOT allowed.
            # -----------------------------------------

            ongoing_match = connection.execute(

                text(
                    """
                    SELECT uuid
                    FROM umatches
                    WHERE
                        (
                            match_initiated_by = :user_uuid
                            OR match_attendedby = :user_uuid
                        )
                        AND status = 'ongoing'
                        AND is_terminated = 0
                    LIMIT 1
                    """
                ),

                {
                    "user_uuid": user_uuid
                }

            ).first()


            if ongoing_match:

                flash(
                    "match initiated already",
                    "error"
                )

                return redirect(
                    url_for("udashboard")
                )


            # -----------------------------------------
            # CHECK JOINING USER BALANCE
            # -----------------------------------------

            if user["money"] < match["amount"]:

                flash(
                    "insufficient money",
                    "error"
                )

                return redirect(
                    url_for("udashboard")
                )


            # -----------------------------------------
            # TERMINATE ALL ACTIVE MATCHES OF USER
            #
            # Only ACTIVE matches are terminated here.
            # Ongoing matches were already checked above.
            # -----------------------------------------

            connection.execute(

                text(
                    """
                    UPDATE umatches
                    SET
                        status = 'terminated',
                        is_terminated = 1
                    WHERE
                        (
                            match_initiated_by = :user_uuid
                            OR match_attendedby = :user_uuid
                        )
                        AND status = 'active'
                        AND is_terminated = 0
                    """
                ),

                {
                    "user_uuid": user_uuid
                }

            )


            # -----------------------------------------
            # REGISTER SECOND USER
            # -----------------------------------------

            connection.execute(

                text(
                    """
                    UPDATE umatches
                    SET
                        match_attendedby = :user_uuid,
                        atimestamp = CURRENT_TIMESTAMP,
                        status = 'ongoing'
                    WHERE uuid = :match_uuid
                    """
                ),

                {
                    "user_uuid": user_uuid,
                    "match_uuid": match_uuid
                }

            )


            # -----------------------------------------
            # STORE ROOM CODE IN SESSION TEMPORARILY
            #
            # Used only to show the joining-user popup.
            # -----------------------------------------

            session["joined_match_roomcode"] = match["roomcode"]


    except Exception:

        flash(
            "Unable to join match",
            "error"
        )

        return redirect(
            url_for("udashboard")
        )


    # -------------------------------------------------
    # RETURN TO DASHBOARD
    # -------------------------------------------------

    return redirect(
        url_for("udashboard")
    )


# =====================================================
# CLEAR JOINED ROOM CODE
# =====================================================

@app.route("/clear-joined-roomcode", methods=["POST"])
def clear_joined_roomcode():

    try:

        session.pop(
            "joined_match_roomcode",
            None
        )

        return "", 204


    except Exception:

        return "", 204

# =====================================================
# MATCH NOTIFICATION
# =====================================================

@app.route("/match-notification")
def match_notification():

    try:

        # -------------------------------------------------
        # CHECK LOGIN
        # -------------------------------------------------

        if not session.get("user_uuid"):

            return {
                "match_found": False
            }


        user_uuid = session.get("user_uuid")


        # -------------------------------------------------
        # FIND LATEST MATCH SELECTED BY ANOTHER USER
        # -------------------------------------------------

        with db_engine.connect() as connection:

            match = connection.execute(

                text(
                    """
                    SELECT
                        uuid,
                        atimestamp
                    FROM umatches
                    WHERE
                        match_initiated_by = :user_uuid
                        AND match_attendedby IS NOT NULL
                        AND status = 'ongoing'
                        AND is_terminated = 0
                    ORDER BY atimestamp DESC
                    LIMIT 1
                    """
                ),

                {
                    "user_uuid": user_uuid
                }

            ).mappings().first()


        if not match:

            return {
                "match_found": False
            }


        return {

            "match_found": True,

            "match_uuid": match["uuid"],

            "atimestamp": str(
                match["atimestamp"]
            )

        }


    except Exception:

        return {
            "match_found": False
        }


@app.route("/add-balance")
def add_balance():

    try:

        # ---------------------------------------------
        # CHECK USER LOGIN
        # ---------------------------------------------

        if not session.get("user_uuid"):
            return redirect(url_for("home"))


        # ---------------------------------------------
        # PAGINATION
        # ---------------------------------------------

        page_input = request.args.get("page", "1").strip()

        try:
            page = int(page_input)
        except ValueError:
            page = 1

        if page < 1:
            page = 1

        per_page = 10

        offset = (page - 1) * per_page


        # ---------------------------------------------
        # FETCH ACCOUNT DETAILS + HISTORY
        # ---------------------------------------------

        with db_engine.connect() as connection:

            # ACCOUNT DETAILS

            account_details = connection.execute(
                text("""
                    SELECT
                        bank_name,
                        account_number,
                        ifsc_code,
                        upiid
                    FROM adetails
                    LIMIT 1
                """)
            ).mappings().first()


            # TOTAL HISTORY COUNT

            total_count = connection.execute(
                text("""
                    SELECT COUNT(*) AS total
                    FROM upaymentproof
                    WHERE user_uuid = :user_uuid
                """),
                {
                    "user_uuid": session["user_uuid"]
                }
            ).scalar()


            # PAYMENT HISTORY

            payment_history = connection.execute(
                text("""
                    SELECT
                        amount,
                        date,
                        utr,
                        status
                    FROM upaymentproof
                    WHERE user_uuid = :user_uuid
                    ORDER BY timestamp DESC
                    LIMIT :limit OFFSET :offset
                """),
                {
                    "user_uuid": session["user_uuid"],
                    "limit": per_page,
                    "offset": offset
                }
            ).mappings().all()


        # ---------------------------------------------
        # PAGINATION CALCULATION
        # ---------------------------------------------

        total_pages = (
            (total_count + per_page - 1) // per_page
        )


        # Prevent invalid page numbers

        if total_pages > 0 and page > total_pages:

            return redirect(
                url_for(
                    "add_balance",
                    page=total_pages
                )
            )


        return render_template(
            "add_balance.html",
            account_details=account_details,
            payment_history=payment_history,
            current_page=page,
            total_pages=total_pages
        )


    except Exception:

        flash(
            "Something went wrong. Please try again.",
            "error"
        )

        return redirect(
            url_for("udashboard")
        )

@app.route("/submit-payment-proof", methods=["POST"])
def submit_payment_proof():

    try:

        # ---------------------------------------------
        # CHECK USER LOGIN
        # ---------------------------------------------

        if not session.get("user_uuid"):
            return redirect(url_for("home"))


        # ---------------------------------------------
        # GET FORM DATA
        # ---------------------------------------------

        payment_date = request.form.get("date", "").strip()
        utr = request.form.get("utr", "").strip()
        amount_input = request.form.get("amount", "").strip()


        # ---------------------------------------------
        # CHECK REQUIRED FIELDS
        # ---------------------------------------------

        if not payment_date or not utr or not amount_input:

            flash(
                "Please provide all payment details.",
                "error"
            )

            return redirect(url_for("add_balance"))


        # ---------------------------------------------
        # VALIDATE AMOUNT
        # ---------------------------------------------

        try:

            amount = Decimal(amount_input)

        except InvalidOperation:

            flash(
                "Invalid amount.",
                "error"
            )

            return redirect(url_for("add_balance"))


        if amount <= 0:

            flash(
                "Invalid amount.",
                "error"
            )

            return redirect(url_for("add_balance"))


        # ---------------------------------------------
        # SAVE PAYMENT PROOF
        # ---------------------------------------------

        try:

            with db_engine.begin() as connection:

                connection.execute(
                    text("""
                        INSERT INTO upaymentproof (
                            user_uuid,
                            date,
                            amount,
                            utr
                        )
                        VALUES (
                            :user_uuid,
                            :payment_date,
                            :amount,
                            :utr
                        )
                    """),
                    {
                        "user_uuid": session["user_uuid"],
                        "payment_date": payment_date,
                        "amount": amount,
                        "utr": utr
                    }
                )


            flash(
                "Payment proof submitted successfully.",
                "success"
            )

        except IntegrityError:

            flash(
                "This UTR has already been submitted.",
                "error"
            )

        except Exception:

            flash(
                "Unable to submit payment proof.",
                "error"
            )


        return redirect(url_for("add_balance"))


    except Exception:

        flash(
            "Something went wrong. Please try again.",
            "error"
        )

        return redirect(
            url_for("add_balance")
        )

@app.route("/withdraw-money", methods=["GET"])
def withdraw_money():

    try:

        # ---------------------------------------------
        # CHECK USER LOGIN
        # ---------------------------------------------

        if not session.get("user_uuid"):
            return redirect(url_for("home"))


        # ---------------------------------------------
        # PAGINATION
        # ---------------------------------------------

        page_input = request.args.get("page", "1").strip()

        try:
            page = int(page_input)
        except ValueError:
            page = 1

        if page < 1:
            page = 1

        per_page = 10

        offset = (page - 1) * per_page


        # ---------------------------------------------
        # FETCH DATA
        # ---------------------------------------------

        with db_engine.connect() as connection:

            # USER WITHDRAWAL DETAILS

            user_details = connection.execute(
                text("""
                    SELECT
                        bank_name,
                        account_number,
                        ifsc_code,
                        upi_id
                    FROM udetails
                    WHERE user_uuid = :user_uuid
                    LIMIT 1
                """),
                {
                    "user_uuid": session["user_uuid"]
                }
            ).mappings().first()


            # TOTAL WITHDRAWAL HISTORY

            total_count = connection.execute(
                text("""
                    SELECT COUNT(*) AS total
                    FROM withdrawal_requests
                    WHERE user_uuid = :user_uuid
                """),
                {
                    "user_uuid": session["user_uuid"]
                }
            ).scalar()


            # WITHDRAWAL HISTORY

            withdrawal_history = connection.execute(
                text("""
                    SELECT
                        amount,
                        medium,
                        status,
                        timestamp
                    FROM withdrawal_requests
                    WHERE user_uuid = :user_uuid
                    ORDER BY timestamp DESC
                    LIMIT :limit OFFSET :offset
                """),
                {
                    "user_uuid": session["user_uuid"],
                    "limit": per_page,
                    "offset": offset
                }
            ).mappings().all()


        # ---------------------------------------------
        # PAGINATION
        # ---------------------------------------------

        total_pages = (
            (total_count + per_page - 1)
            // per_page
        )


        # Prevent invalid pages

        if total_pages > 0 and page > total_pages:

            return redirect(
                url_for(
                    "withdraw_money",
                    page=total_pages
                )
            )


        return render_template(
            "withdraw_money.html",
            user_details=user_details,
            withdrawal_history=withdrawal_history,
            current_page=page,
            total_pages=total_pages
        )


    except Exception:

        flash(
            "Something went wrong. Please try again.",
            "error"
        )

        return redirect(
            url_for("udashboard")
        )



@app.route("/submit-withdrawal-details", methods=["POST"])
def submit_withdrawal_details():

    try:

        # ---------------------------------------------
        # CHECK USER LOGIN
        # ---------------------------------------------

        if not session.get("user_uuid"):
            return redirect(url_for("home"))


        # ---------------------------------------------
        # GET FORM DATA
        # ---------------------------------------------

        bank_name = request.form.get(
            "bank_name",
            ""
        ).strip()

        account_number = request.form.get(
            "account_number",
            ""
        ).strip()

        ifsc_code = request.form.get(
            "ifsc_code",
            ""
        ).strip()

        upi_id = request.form.get(
            "upi_id",
            ""
        ).strip()


        # ---------------------------------------------
        # VALIDATION
        # ---------------------------------------------

        bank_details_complete = (
            bool(bank_name)
            and bool(account_number)
            and bool(ifsc_code)
        )

        upi_complete = bool(upi_id)


        # ---------------------------------------------
        # ALLOWED CASES
        #
        # 1. BANK DETAILS ONLY
        # 2. UPI ONLY
        # 3. BANK + UPI
        #
        # Anything else is invalid.
        # ---------------------------------------------

        if not bank_details_complete and not upi_complete:

            flash(
                "Please provide complete bank details or a UPI ID.",
                "error"
            )

            return redirect(
                url_for("withdraw_money")
            )


        # If some bank information is provided,
        # all three bank fields must be provided.

        bank_any_entered = (
            bool(bank_name)
            or bool(account_number)
            or bool(ifsc_code)
        )

        if bank_any_entered and not bank_details_complete:

            flash(
                "Please provide Bank Name, Account Number and IFSC Code together.",
                "error"
            )

            return redirect(
                url_for("withdraw_money")
            )


        # ---------------------------------------------
        # SAVE DETAILS
        # ---------------------------------------------

        try:

            with db_engine.begin() as connection:

                existing_details = connection.execute(
                    text("""
                        SELECT user_uuid
                        FROM udetails
                        WHERE user_uuid = :user_uuid
                        LIMIT 1
                    """),
                    {
                        "user_uuid": session["user_uuid"]
                    }
                ).first()


                if existing_details:

                    connection.execute(
                        text("""
                            UPDATE udetails
                            SET
                                bank_name = :bank_name,
                                account_number = :account_number,
                                ifsc_code = :ifsc_code,
                                upi_id = :upi_id
                            WHERE user_uuid = :user_uuid
                        """),
                        {
                            "user_uuid": session["user_uuid"],
                            "bank_name": (
                                bank_name
                                if bank_name
                                else "Not Added"
                            ),
                            "account_number": (
                                account_number
                                if account_number
                                else "Not Added"
                            ),
                            "ifsc_code": (
                                ifsc_code
                                if ifsc_code
                                else "Not Added"
                            ),
                            "upi_id": (
                                upi_id
                                if upi_id
                                else "Not Added"
                            )
                        }
                    )

                else:

                    connection.execute(
                        text("""
                            INSERT INTO udetails (
                                user_uuid,
                                bank_name,
                                account_number,
                                ifsc_code,
                                upi_id
                            )
                            VALUES (
                                :user_uuid,
                                :bank_name,
                                :account_number,
                                :ifsc_code,
                                :upi_id
                            )
                        """),
                        {
                            "user_uuid": session["user_uuid"],
                            "bank_name": (
                                bank_name
                                if bank_name
                                else "Not Added"
                            ),
                            "account_number": (
                                account_number
                                if account_number
                                else "Not Added"
                            ),
                            "ifsc_code": (
                                ifsc_code
                                if ifsc_code
                                else "Not Added"
                            ),
                            "upi_id": (
                                upi_id
                                if upi_id
                                else "Not Added"
                            )
                        }
                    )


            flash(
                "Your withdrawal details have been saved successfully.",
                "success"
            )

        except Exception:

            flash(
                "Unable to save your details. Please try again.",
                "error"
            )


        return redirect(
            url_for("withdraw_money")
        )


    except Exception:

        flash(
            "Something went wrong. Please try again.",
            "error"
        )

        return redirect(
            url_for("withdraw_money")
        )



@app.route("/submit-withdrawal-request", methods=["POST"])
def submit_withdrawal_request():

    try:

        # ---------------------------------------------
        # CHECK USER LOGIN
        # ---------------------------------------------

        if not session.get("user_uuid"):
            return redirect(url_for("home"))


        # ---------------------------------------------
        # GET FORM DATA
        # ---------------------------------------------

        amount_input = request.form.get(
            "amount",
            ""
        ).strip()

        medium = request.form.get(
            "medium",
            ""
        ).strip().lower()


        # ---------------------------------------------
        # CHECK AMOUNT
        # ---------------------------------------------

        try:

            amount = Decimal(amount_input)

        except InvalidOperation:

            flash(
                "Invalid withdrawal amount.",
                "error"
            )

            return redirect(
                url_for("withdraw_money")
            )


        if amount <= 0:

            flash(
                "Invalid withdrawal amount.",
                "error"
            )

            return redirect(
                url_for("withdraw_money")
            )


        # ---------------------------------------------
        # CHECK MEDIUM
        # ---------------------------------------------

        if medium not in ("bank", "upi"):

            flash(
                "Please select a withdrawal medium.",
                "error"
            )

            return redirect(
                url_for("withdraw_money")
            )


        # ---------------------------------------------
        # CHECK BALANCE + USER DETAILS
        # ---------------------------------------------

        try:

            with db_engine.begin() as connection:

                user = connection.execute(
                    text("""
                        SELECT money
                        FROM lpusers
                        WHERE uuid = :user_uuid
                        FOR UPDATE
                    """),
                    {
                        "user_uuid": session["user_uuid"]
                    }
                ).mappings().first()


                if not user:

                    flash(
                        "User account not found.",
                        "error"
                    )

                    return redirect(
                        url_for("withdraw_money")
                    )


                # -----------------------------------------
                # CHECK AVAILABLE BALANCE
                # -----------------------------------------

                if Decimal(str(user["money"])) < amount:

                    flash(
                        "Insufficient balance.",
                        "error"
                    )

                    return redirect(
                        url_for("withdraw_money")
                    )


                # -----------------------------------------
                # FETCH WITHDRAWAL DETAILS
                # -----------------------------------------

                details = connection.execute(
                    text("""
                        SELECT
                            bank_name,
                            account_number,
                            ifsc_code,
                            upi_id
                        FROM udetails
                        WHERE user_uuid = :user_uuid
                        LIMIT 1
                    """),
                    {
                        "user_uuid": session["user_uuid"]
                    }
                ).mappings().first()


                # -----------------------------------------
                # CHECK DETAILS EXIST
                # -----------------------------------------

                if not details:

                    flash(
                        "Please submit your withdrawal details first.",
                        "error"
                    )

                    return redirect(
                        url_for("withdraw_money")
                    )


                # -----------------------------------------
                # CHECK SELECTED MEDIUM
                # -----------------------------------------

                if medium == "upi":

                    if (
                        not details["upi_id"]
                        or details["upi_id"] == "Not Added"
                    ):

                        flash(
                            "UPI ID is not available in your details.",
                            "error"
                        )

                        return redirect(
                            url_for("withdraw_money")
                        )


                elif medium == "bank":

                    if (
                        not details["bank_name"]
                        or details["bank_name"] == "Not Added"
                        or not details["account_number"]
                        or details["account_number"] == "Not Added"
                        or not details["ifsc_code"]
                        or details["ifsc_code"] == "Not Added"
                    ):

                        flash(
                            "Complete bank details are not available.",
                            "error"
                        )

                        return redirect(
                            url_for("withdraw_money")
                        )


                # -----------------------------------------
                # CREATE WITHDRAWAL REQUEST
                # -----------------------------------------

                withdrawal_uuid = str(uuid.uuid4())

                connection.execute(
                    text("""
                        INSERT INTO withdrawal_requests (
                            uuid,
                            user_uuid,
                            amount,
                            medium
                        )
                        VALUES (
                            :uuid,
                            :user_uuid,
                            :amount,
                            :medium
                        )
                    """),
                    {
                        "uuid": withdrawal_uuid,
                        "user_uuid": session["user_uuid"],
                        "amount": amount,
                        "medium": medium
                    }
                )


            flash(
                "Withdrawal request submitted successfully.",
                "success"
            )

        except Exception:

            flash(
                "Unable to submit withdrawal request.",
                "error"
            )


        return redirect(
            url_for("withdraw_money")
        )


    except Exception:

        flash(
            "Something went wrong. Please try again.",
            "error"
        )

        return redirect(
            url_for("withdraw_money")
        )



@app.route("/your-matches")
def your_matches():

    try:

        # ---------------------------------------------
        # CHECK USER LOGIN
        # ---------------------------------------------

        if not session.get("user_uuid"):
            return redirect(url_for("home"))


        # ---------------------------------------------
        # PAGINATION
        # ---------------------------------------------

        page_input = request.args.get("page", "1").strip()

        try:
            page = int(page_input)
        except ValueError:
            page = 1

        if page < 1:
            page = 1

        per_page = 15

        offset = (page - 1) * per_page


        # ---------------------------------------------
        # FETCH MATCH HISTORY
        # ---------------------------------------------

        with db_engine.connect() as connection:

            # -----------------------------------------
            # TOTAL MATCH COUNT
            # -----------------------------------------

            total_count = connection.execute(
                text("""
                    SELECT COUNT(*) AS total
                    FROM umatches
                    WHERE
                        match_initiated_by = :user_uuid
                        OR match_attendedby = :user_uuid
                """),
                {
                    "user_uuid": session["user_uuid"]
                }
            ).scalar()


            # -----------------------------------------
            # MATCH HISTORY
            # -----------------------------------------

            match_history = connection.execute(
                text("""
                    SELECT

                        m.uuid AS match_uuid,

                        u1.username AS user1_name,

                        u2.username AS user2_name,

                        m.timestamp AS match_date,

                        m.amount AS amount,

                        m.status AS match_status,

                        r.status AS result_status,

                        rw.username AS winner_name

                    FROM umatches m

                    INNER JOIN lpusers u1
                        ON u1.uuid = m.match_initiated_by

                    LEFT JOIN lpusers u2
                        ON u2.uuid = m.match_attendedby

                    LEFT JOIN uresults r
                        ON r.matchuuid = m.uuid

                    LEFT JOIN lpusers rw
                        ON rw.uuid = r.winner

                    WHERE
                        m.match_initiated_by = :user_uuid
                        OR m.match_attendedby = :user_uuid

                    ORDER BY m.timestamp DESC

                    LIMIT :limit
                    OFFSET :offset
                """),
                {
                    "user_uuid": session["user_uuid"],
                    "limit": per_page,
                    "offset": offset
                }
            ).mappings().all()


        # ---------------------------------------------
        # PAGINATION
        # ---------------------------------------------

        total_pages = (
            (total_count + per_page - 1)
            // per_page
        )


        # ---------------------------------------------
        # PREVENT INVALID PAGE
        # ---------------------------------------------

        if total_pages > 0 and page > total_pages:

            return redirect(
                url_for(
                    "your_matches",
                    page=total_pages
                )
            )


        # ---------------------------------------------
        # RENDER PAGE
        # ---------------------------------------------

        return render_template(
            "your_matches.html",
            match_history=match_history,
            current_page=page,
            total_pages=total_pages
        )


    except Exception:

        flash(
            "Something went wrong. Please try again.",
            "error"
        )

        return redirect(
            url_for("udashboard")
        )


# =====================================================
# YOUR PROFILE
# =====================================================

@app.route("/profile")
def profile():

    try:

        if not session.get("user_uuid"):
            return redirect(url_for("home"))

        with db_engine.connect() as connection:

            user = connection.execute(
                text("""
                    SELECT
                        username,
                        phone_number,
                        money
                    FROM lpusers
                    WHERE uuid = :user_uuid
                    LIMIT 1
                """),
                {
                    "user_uuid": session["user_uuid"]
                }
            ).mappings().first()

        if not user:
            session.clear()
            return redirect(url_for("home"))

        return render_template(
            "profile.html",
            user=user
        )


    except Exception:

        flash(
            "Something went wrong. Please try again.",
            "error"
        )

        return redirect(
            url_for("udashboard")
        )


# =====================================================
# UPDATE PASSWORD
# =====================================================

@app.route("/update-password", methods=["POST"])
def update_password():

    try:

        if not session.get("user_uuid"):
            return redirect(url_for("home"))

        current_password = request.form.get(
            "current_password",
            ""
        )

        new_password = request.form.get(
            "new_password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )


        # ---------------------------------------------
        # CHECK EMPTY FIELDS
        # ---------------------------------------------

        if not current_password or not new_password or not confirm_password:

            flash(
                "Please fill all password fields.",
                "error"
            )

            return redirect(url_for("profile"))


        # ---------------------------------------------
        # PASSWORD LENGTH
        # ---------------------------------------------

        if len(new_password) > 20:

            flash(
                "Password cannot be more than 20 characters.",
                "error"
            )

            return redirect(url_for("profile"))


        if len(new_password) < 6:

            flash(
                "Password must be at least 6 characters.",
                "error"
            )

            return redirect(url_for("profile"))


        # ---------------------------------------------
        # CONFIRM PASSWORD
        # ---------------------------------------------

        if new_password != confirm_password:

            flash(
                "New passwords do not match.",
                "error"
            )

            return redirect(url_for("profile"))


        # ---------------------------------------------
        # GET CURRENT PASSWORD
        # ---------------------------------------------

        with db_engine.connect() as connection:

            user = connection.execute(
                text("""
                    SELECT password
                    FROM lpusers
                    WHERE uuid = :user_uuid
                    LIMIT 1
                """),
                {
                    "user_uuid": session["user_uuid"]
                }
            ).mappings().first()


        if not user:

            session.clear()

            return redirect(url_for("home"))


        # ---------------------------------------------
        # VERIFY CURRENT PASSWORD
        # ---------------------------------------------

        if not bcrypt.checkpw(
            current_password.encode("utf-8"),
            user["password"].encode("utf-8")
        ):

            flash(
                "Current password is incorrect.",
                "error"
            )

            return redirect(url_for("profile"))


        # ---------------------------------------------
        # HASH NEW PASSWORD
        # ---------------------------------------------

        hashed_password = bcrypt.hashpw(
            new_password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")


        # ---------------------------------------------
        # UPDATE PASSWORD
        # ---------------------------------------------

        try:

            with db_engine.begin() as connection:

                connection.execute(
                    text("""
                        UPDATE lpusers
                        SET password = :password
                        WHERE uuid = :user_uuid
                    """),
                    {
                        "password": hashed_password,
                        "user_uuid": session["user_uuid"]
                    }
                )

            flash(
                "Password updated successfully.",
                "success"
            )

        except Exception:

            flash(
                "Unable to update password.",
                "error"
            )


        return redirect(url_for("profile"))


    except Exception:

        flash(
            "Something went wrong. Please try again.",
            "error"
        )

        return redirect(
            url_for("profile")
        )

@app.route("/logout")
def logout():

    try:

        # -------------------------------------------------
        # CLEAR CURRENT USER SESSION
        # -------------------------------------------------

        session.clear()


        # -------------------------------------------------
        # RETURN TO LOGIN
        # -------------------------------------------------

        return redirect(
            url_for("home")
        )


    except Exception:

        return redirect(
            url_for("home")
        )


# =====================================================
# APPLICATION START
# =====================================================

if __name__ == "__main__":

    app.run(debug=True)