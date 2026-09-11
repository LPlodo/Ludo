from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session
)

import os
import uuid
import time

from decimal import Decimal

from sqlalchemy import text
from config import initialize_database

# =====================================================
# DATABASE
# =====================================================

db_engine = initialize_database()


# =====================================================
# ADMIN BLUEPRINT
# =====================================================

admin_bp = Blueprint(
    "admin",
    __name__,
    url_prefix="/admin"
)


# =====================================================
# ADMIN CREDENTIALS
# =====================================================

ADMIN_USERNAME = os.environ["ADMIN_USERNAME"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]
STATUS_PASSWORD = os.environ["STATUS_PASSWORD"]
ADMININTERNAL = os.environ["ADMININTERNAL"]

# =====================================================
# ADMIN LOGIN
# =====================================================

@admin_bp.route("/login", methods=["GET", "POST"])
def admin_login():

    try:

        # ---------------------------------------------
        # ALREADY LOGGED IN
        # ---------------------------------------------

        if session.get("admin_logged_in"):

            return redirect(
                url_for("admin.admin_dashboard")
            )


        # ---------------------------------------------
        # LOGIN SUBMISSION
        # ---------------------------------------------

        if request.method == "POST":

            username = request.form.get(
                "username",
                ""
            ).strip()

            password = request.form.get(
                "password",
                ""
            )


            # -----------------------------------------
            # CHECK CREDENTIALS
            # -----------------------------------------

            if (
                username == ADMIN_USERNAME
                and password == ADMIN_PASSWORD
            ):

                session["admin_logged_in"] = True
                session["admin_username"] = username


                # -------------------------------------
                # LOG SUCCESSFUL LOGIN
                # -------------------------------------

                with db_engine.begin() as connection:

                    connection.execute(
                        text(
                            """
                            INSERT INTO admin_activity_logs (
                                uuid,
                                admin_username,
                                action,
                                description,
                                target_uuid,
                                target_type,
                                ip_address,
                                user_agent
                            )
                            VALUES (
                                :uuid,
                                :admin_username,
                                :action,
                                :description,
                                :target_uuid,
                                :target_type,
                                :ip_address,
                                :user_agent
                            )
                            """
                        ),
                        {
                            "uuid": str(uuid.uuid4()),

                            "admin_username": username,

                            "action": "LOGIN_SUCCESS",

                            "description":
                                "Admin login successful.",

                            "target_uuid":
                                "admin",

                            "target_type":
                                "ADMIN",

                            "ip_address":
                                request.remote_addr,

                            "user_agent":
                                request.headers.get(
                                    "User-Agent",
                                    ""
                                )
                        }
                    )


                return redirect(
                    url_for("admin.admin_dashboard")
                )


            # -----------------------------------------
            # LOG FAILED LOGIN
            # -----------------------------------------

            with db_engine.begin() as connection:

                connection.execute(
                    text(
                        """
                        INSERT INTO admin_activity_logs (
                            uuid,
                            admin_username,
                            action,
                            description,
                            target_uuid,
                            target_type,
                            ip_address,
                            user_agent
                        )
                        VALUES (
                            :uuid,
                            :admin_username,
                            :action,
                            :description,
                            :target_uuid,
                            :target_type,
                            :ip_address,
                            :user_agent
                        )
                        """
                    ),
                    {
                        "uuid": str(uuid.uuid4()),

                        "admin_username":
                            username
                            if username
                            else "unknown",

                        "action":
                            "LOGIN_FAILED",

                        "description":
                            "Admin login failed due to invalid credentials.",

                        "target_uuid":
                            "admin",

                        "target_type":
                            "ADMIN",

                        "ip_address":
                            request.remote_addr,

                        "user_agent":
                            request.headers.get(
                                "User-Agent",
                                ""
                            )
                    }
                )


            flash(
                "Invalid admin credentials.",
                "error"
            )


        return render_template(
            "admin/login.html"
        )


    except Exception:

        flash(
            "Something went wrong. Please try again.",
            "error"
        )

        return redirect(
            url_for("admin.admin_login")
        )

# =====================================================
# ADMIN DASHBOARD
# =====================================================

@admin_bp.route("/dashboard")
def admin_dashboard():

    try:

        if not session.get("admin_logged_in"):

            return redirect(
                url_for("admin.admin_login")
            )


        # ---------------------------------------------
        # WINNERS PAGE
        # ---------------------------------------------

        page_input = request.args.get(
            "page",
            "1"
        ).strip()

        try:

            page = int(page_input)

        except ValueError:

            page = 1


        if page < 1:

            page = 1


        per_page = 7

        offset = (page - 1) * per_page


        with db_engine.connect() as connection:

            # =========================================
            # ADMIN ACCOUNT DETAILS
            # =========================================

            admin_details = connection.execute(
                text("""
                    SELECT
                        bank_name,
                        account_number,
                        ifsc_code,
                        upiid,
                        contact
                    FROM adetails
                    LIMIT 1
                """)
            ).mappings().first()


            # =========================================
            # TOTAL WINNER RESULTS
            # =========================================

            total_winners = connection.execute(
                text("""
                    SELECT COUNT(*) AS total
                    FROM uresults
                    WHERE status = 'hold'
                """)
            ).scalar()


            # =========================================
            # WINNER MATCHES
            # =========================================

            winner_matches = connection.execute(
                text("""
                    SELECT

                        r.matchuuid,

                        r.user1uuid,
                        u1.username AS user1_name,
                        r.user1option,

                        r.user2uuid,
                        u2.username AS user2_name,
                        r.user2option,

                        r.status AS result_status,
                        r.remark,

                        m.amount,
                        m.timestamp AS match_date,
                        m.roomcode,
                        m.status AS match_status,
                        m.is_terminated

                    FROM uresults r

                    INNER JOIN umatches m
                        ON m.uuid = r.matchuuid

                    INNER JOIN lpusers u1
                        ON u1.uuid = r.user1uuid

                    LEFT JOIN lpusers u2
                        ON u2.uuid = r.user2uuid

                    WHERE r.status = 'hold'

                    ORDER BY m.timestamp DESC

                    LIMIT :limit
                    OFFSET :offset
                """),
                {
                    "limit": per_page,
                    "offset": offset
                }
            ).mappings().all()


        # ---------------------------------------------
        # TOTAL PAGES
        # ---------------------------------------------

        total_pages = (
            total_winners + per_page - 1
        ) // per_page


        # ---------------------------------------------
        # INVALID PAGE
        # ---------------------------------------------

        if total_pages > 0 and page > total_pages:

            return redirect(
                url_for(
                    "admin.admin_dashboard",
                    page=total_pages
                )
            )


        # ---------------------------------------------
        # LOG DASHBOARD VIEW
        # ---------------------------------------------

        with db_engine.begin() as connection:

            connection.execute(
                text(
                    """
                    INSERT INTO admin_activity_logs (
                        uuid,
                        admin_username,
                        action,
                        description,
                        target_uuid,
                        target_type,
                        ip_address,
                        user_agent
                    )
                    VALUES (
                        :uuid,
                        :admin_username,
                        :action,
                        :description,
                        :target_uuid,
                        :target_type,
                        :ip_address,
                        :user_agent
                    )
                    """
                ),
                {
                    "uuid": str(uuid.uuid4()),

                    "admin_username":
                        session.get(
                            "admin_username",
                            ADMIN_USERNAME
                        ),

                    "action":
                        "DASHBOARD_VIEW",

                    "description":
                        f"Admin dashboard viewed. Page: {page}",

                    "target_uuid":
                        "admin",

                    "target_type":
                        "ADMIN",

                    "ip_address":
                        request.remote_addr,

                    "user_agent":
                        request.headers.get(
                            "User-Agent",
                            ""
                        )
                }
            )


        return render_template(
            "admin/dashboard.html",

            admin_details=admin_details,

            winner_matches=winner_matches,

            current_page=page,

            total_pages=total_pages
        )


    except Exception:

        flash(
            "Something went wrong. Please try again.",
            "error"
        )

        return redirect(
            url_for("admin.admin_dashboard")
        )


# =====================================================
# COMPLETE WINNER RESULT
# =====================================================

@admin_bp.route("/complete-result", methods=["POST"])
def complete_result():

    if not session.get("admin_logged_in"):

        return redirect(
            url_for("admin.admin_login")
        )


    matchuuid = request.form.get(
        "matchuuid",
        ""
    ).strip()

    winner_option = request.form.get(
        "winner_option",
        ""
    ).strip().lower()

    remark = request.form.get(
        "remark",
        ""
    ).strip()


    # ---------------------------------------------
    # BASIC VALIDATION
    # ---------------------------------------------

    if not matchuuid:

        flash(
            "Match information is missing.",
            "error"
        )

        return redirect(
            url_for("admin.admin_dashboard")
        )


    if winner_option not in ("user1", "user2"):

        flash(
            "Please select a valid winner.",
            "error"
        )

        return redirect(
            url_for("admin.admin_dashboard")
        )


    # ---------------------------------------------
    # REMARK LIMIT
    # ---------------------------------------------

    if len(remark) > 70:

        flash(
            "Remark cannot be more than 70 characters.",
            "error"
        )

        return redirect(
            url_for("admin.admin_dashboard")
        )


    try:

        with db_engine.begin() as connection:

            # =========================================
            # LOCK RESULT
            # =========================================

            result = connection.execute(
                text("""
                    SELECT
                        matchuuid,
                        user1uuid,
                        user1option,
                        user2uuid,
                        user2option,
                        winner,
                        status
                    FROM uresults
                    WHERE matchuuid = :matchuuid
                    LIMIT 1
                    FOR UPDATE
                """),
                {
                    "matchuuid": matchuuid
                }
            ).mappings().first()


            if not result:

                connection.execute(
                    text("""
                        INSERT INTO admin_activity_logs (
                            uuid,
                            admin_username,
                            action,
                            description,
                            target_uuid,
                            target_type,
                            ip_address,
                            user_agent
                        )
                        VALUES (
                            :uuid,
                            :admin_username,
                            :action,
                            :description,
                            :target_uuid,
                            :target_type,
                            :ip_address,
                            :user_agent
                        )
                    """),
                    {
                        "uuid": str(uuid.uuid4()),

                        "admin_username":
                            session.get(
                                "admin_username",
                                ADMIN_USERNAME
                            ),

                        "action":
                            "MATCH_COMPLETION_FAILED",

                        "description":
                            "Admin attempted to complete a match, but the match result was not found.",

                        "target_uuid":
                            matchuuid,

                        "target_type":
                            "MATCH",

                        "ip_address":
                            request.remote_addr,

                        "user_agent":
                            request.headers.get(
                                "User-Agent",
                                ""
                            )
                    }
                )

                flash(
                    "Match result not found.",
                    "error"
                )

                return redirect(
                    url_for("admin.admin_dashboard")
                )


            # =========================================
            # ALREADY COMPLETED
            # =========================================

            if result["status"] == "completed":

                connection.execute(
                    text("""
                        INSERT INTO admin_activity_logs (
                            uuid,
                            admin_username,
                            action,
                            description,
                            target_uuid,
                            target_type,
                            ip_address,
                            user_agent
                        )
                        VALUES (
                            :uuid,
                            :admin_username,
                            :action,
                            :description,
                            :target_uuid,
                            :target_type,
                            :ip_address,
                            :user_agent
                        )
                    """),
                    {
                        "uuid": str(uuid.uuid4()),

                        "admin_username":
                            session.get(
                                "admin_username",
                                ADMIN_USERNAME
                            ),

                        "action":
                            "MATCH_COMPLETION_FAILED",

                        "description":
                            "Admin attempted to complete a match that was already completed.",

                        "target_uuid":
                            matchuuid,

                        "target_type":
                            "MATCH",

                        "ip_address":
                            request.remote_addr,

                        "user_agent":
                            request.headers.get(
                                "User-Agent",
                                ""
                            )
                    }
                )

                flash(
                    "This match has already been completed.",
                    "error"
                )

                return redirect(
                    url_for("admin.admin_dashboard")
                )


            # =========================================
            # USER 2 MUST EXIST
            # =========================================

            if not result["user2uuid"]:

                connection.execute(
                    text("""
                        INSERT INTO admin_activity_logs (
                            uuid,
                            admin_username,
                            action,
                            description,
                            target_uuid,
                            target_type,
                            ip_address,
                            user_agent
                        )
                        VALUES (
                            :uuid,
                            :admin_username,
                            :action,
                            :description,
                            :target_uuid,
                            :target_type,
                            :ip_address,
                            :user_agent
                        )
                    """),
                    {
                        "uuid": str(uuid.uuid4()),

                        "admin_username":
                            session.get(
                                "admin_username",
                                ADMIN_USERNAME
                            ),

                        "action":
                            "MATCH_COMPLETION_FAILED",

                        "description":
                            "Admin attempted to complete a match that does not have two users.",

                        "target_uuid":
                            matchuuid,

                        "target_type":
                            "MATCH",

                        "ip_address":
                            request.remote_addr,

                        "user_agent":
                            request.headers.get(
                                "User-Agent",
                                ""
                            )
                    }
                )

                flash(
                    "This match does not have two users.",
                    "error"
                )

                return redirect(
                    url_for("admin.admin_dashboard")
                )


            # =========================================
            # LOCK MATCH
            # =========================================

            match = connection.execute(
                text("""
                    SELECT
                        uuid,
                        amount,
                        roomcode,
                        status,
                        is_terminated
                    FROM umatches
                    WHERE uuid = :matchuuid
                    LIMIT 1
                    FOR UPDATE
                """),
                {
                    "matchuuid": matchuuid
                }
            ).mappings().first()


            if not match:

                connection.execute(
                    text("""
                        INSERT INTO admin_activity_logs (
                            uuid,
                            admin_username,
                            action,
                            description,
                            target_uuid,
                            target_type,
                            ip_address,
                            user_agent
                        )
                        VALUES (
                            :uuid,
                            :admin_username,
                            :action,
                            :description,
                            :target_uuid,
                            :target_type,
                            :ip_address,
                            :user_agent
                        )
                    """),
                    {
                        "uuid": str(uuid.uuid4()),

                        "admin_username":
                            session.get(
                                "admin_username",
                                ADMIN_USERNAME
                            ),

                        "action":
                            "MATCH_COMPLETION_FAILED",

                        "description":
                            "Admin attempted to complete a match, but the match record was not found.",

                        "target_uuid":
                            matchuuid,

                        "target_type":
                            "MATCH",

                        "ip_address":
                            request.remote_addr,

                        "user_agent":
                            request.headers.get(
                                "User-Agent",
                                ""
                            )
                    }
                )

                flash(
                    "Match not found.",
                    "error"
                )

                return redirect(
                    url_for("admin.admin_dashboard")
                )


            # =========================================
            # MATCH ALREADY COMPLETED / TERMINATED
            # =========================================

            if (
                match["status"] == "completed"
                or match["is_terminated"]
            ):

                connection.execute(
                    text("""
                        INSERT INTO admin_activity_logs (
                            uuid,
                            admin_username,
                            action,
                            description,
                            target_uuid,
                            target_type,
                            ip_address,
                            user_agent
                        )
                        VALUES (
                            :uuid,
                            :admin_username,
                            :action,
                            :description,
                            :target_uuid,
                            :target_type,
                            :ip_address,
                            :user_agent
                        )
                    """),
                    {
                        "uuid": str(uuid.uuid4()),

                        "admin_username":
                            session.get(
                                "admin_username",
                                ADMIN_USERNAME
                            ),

                        "action":
                            "MATCH_COMPLETION_FAILED",

                        "description":
                            "Admin attempted to complete a match that was already completed or terminated.",

                        "target_uuid":
                            matchuuid,

                        "target_type":
                            "MATCH",

                        "ip_address":
                            request.remote_addr,

                        "user_agent":
                            request.headers.get(
                                "User-Agent",
                                ""
                            )
                    }
                )

                flash(
                    "This match has already been completed.",
                    "error"
                )

                return redirect(
                    url_for("admin.admin_dashboard")
                )


            # =========================================
            # DETERMINE WINNER / LOSER
            # =========================================

            if winner_option == "user1":

                winner_uuid = result["user1uuid"]

                loser_uuid = result["user2uuid"]

            else:

                winner_uuid = result["user2uuid"]

                loser_uuid = result["user1uuid"]


            # =========================================
            # MATCH AMOUNT
            # =========================================

            amount = Decimal(
                str(match["amount"])
            )


            winner_amount = amount * Decimal("1.88")

            total_amount = amount * Decimal("2.00")

            commission = (
                total_amount
                - (total_amount * Decimal("0.94"))
            )


            # =========================================
            # LOCK WINNER + LOSER
            # =========================================

            users = connection.execute(
                text("""
                    SELECT
                        uuid,
                        money
                    FROM lpusers
                    WHERE uuid IN (
                        :winner_uuid,
                        :loser_uuid
                    )
                    FOR UPDATE
                """),
                {
                    "winner_uuid": winner_uuid,
                    "loser_uuid": loser_uuid
                }
            ).mappings().all()


            user_balances = {
                user["uuid"]: Decimal(
                    str(user["money"])
                )
                for user in users
            }


            if winner_uuid not in user_balances:

                connection.execute(
                    text("""
                        INSERT INTO admin_activity_logs (
                            uuid,
                            admin_username,
                            action,
                            description,
                            target_uuid,
                            target_type,
                            ip_address,
                            user_agent
                        )
                        VALUES (
                            :uuid,
                            :admin_username,
                            :action,
                            :description,
                            :target_uuid,
                            :target_type,
                            :ip_address,
                            :user_agent
                        )
                    """),
                    {
                        "uuid": str(uuid.uuid4()),

                        "admin_username":
                            session.get(
                                "admin_username",
                                ADMIN_USERNAME
                            ),

                        "action":
                            "MATCH_COMPLETION_FAILED",

                        "description":
                            "Admin attempted to complete a match, but the winner account was not found.",

                        "target_uuid":
                            matchuuid,

                        "target_type":
                            "MATCH",

                        "ip_address":
                            request.remote_addr,

                        "user_agent":
                            request.headers.get(
                                "User-Agent",
                                ""
                            )
                    }
                )

                flash(
                    "Winner account not found.",
                    "error"
                )

                return redirect(
                    url_for("admin.admin_dashboard")
                )


            if loser_uuid not in user_balances:

                connection.execute(
                    text("""
                        INSERT INTO admin_activity_logs (
                            uuid,
                            admin_username,
                            action,
                            description,
                            target_uuid,
                            target_type,
                            ip_address,
                            user_agent
                        )
                        VALUES (
                            :uuid,
                            :admin_username,
                            :action,
                            :description,
                            :target_uuid,
                            :target_type,
                            :ip_address,
                            :user_agent
                        )
                    """),
                    {
                        "uuid": str(uuid.uuid4()),

                        "admin_username":
                            session.get(
                                "admin_username",
                                ADMIN_USERNAME
                            ),

                        "action":
                            "MATCH_COMPLETION_FAILED",

                        "description":
                            "Admin attempted to complete a match, but the loser account was not found.",

                        "target_uuid":
                            matchuuid,

                        "target_type":
                            "MATCH",

                        "ip_address":
                            request.remote_addr,

                        "user_agent":
                            request.headers.get(
                                "User-Agent",
                                ""
                            )
                    }
                )

                flash(
                    "Loser account not found.",
                    "error"
                )

                return redirect(
                    url_for("admin.admin_dashboard")
                )


            # =========================================
            # CHECK LOSER BALANCE
            # =========================================

            if user_balances[loser_uuid] < amount:

                connection.execute(
                    text("""
                        INSERT INTO admin_activity_logs (
                            uuid,
                            admin_username,
                            action,
                            description,
                            target_uuid,
                            target_type,
                            ip_address,
                            user_agent
                        )
                        VALUES (
                            :uuid,
                            :admin_username,
                            :action,
                            :description,
                            :target_uuid,
                            :target_type,
                            :ip_address,
                            :user_agent
                        )
                    """),
                    {
                        "uuid": str(uuid.uuid4()),

                        "admin_username":
                            session.get(
                                "admin_username",
                                ADMIN_USERNAME
                            ),

                        "action":
                            "MATCH_COMPLETION_FAILED",

                        "description":
                            "Admin attempted to complete a match, but the loser did not have sufficient balance.",

                        "target_uuid":
                            matchuuid,

                        "target_type":
                            "MATCH",

                        "ip_address":
                            request.remote_addr,

                        "user_agent":
                            request.headers.get(
                                "User-Agent",
                                ""
                            )
                    }
                )

                flash(
                    "Loser does not have enough balance to complete this match.",
                    "error"
                )

                return redirect(
                    url_for("admin.admin_dashboard")
                )


            # =========================================
            # CREDIT WINNER
            # =========================================

            connection.execute(
                text("""
                    UPDATE lpusers
                    SET money = money + :winner_amount
                    WHERE uuid = :winner_uuid
                """),
                {
                    "winner_amount": winner_amount,
                    "winner_uuid": winner_uuid
                }
            )


            # =========================================
            # DEDUCT LOSER
            # =========================================

            connection.execute(
                text("""
                    UPDATE lpusers
                    SET money = money - :loser_amount
                    WHERE uuid = :loser_uuid
                """),
                {
                    "loser_amount": amount,
                    "loser_uuid": loser_uuid
                }
            )


            # =========================================
            # UPDATE URESULTS
            # =========================================

            connection.execute(
                text("""
                    UPDATE uresults

                    SET
                        winner = :winner_uuid,
                        status = 'completed',
                        remark = :remark

                    WHERE matchuuid = :matchuuid
                """),
                {
                    "winner_uuid": winner_uuid,
                    "remark": remark or None,
                    "matchuuid": matchuuid
                }
            )


            # =========================================
            # UPDATE UMATCHES
            # =========================================

            connection.execute(
                text("""
                    UPDATE umatches

                    SET
                        status = 'completed',
                        is_terminated = 1

                    WHERE uuid = :matchuuid
                """),
                {
                    "matchuuid": matchuuid
                }
            )


            # =========================================
            # SAVE COMMISSION
            # =========================================

            commission_uuid = str(
                uuid.uuid4()
            )


            connection.execute(
                text("""
                    INSERT INTO acommission (

                        uuid,
                        roomcode,
                        matchuuid,
                        total_amount,
                        commision

                    )

                    VALUES (

                        :uuid,
                        :roomcode,
                        :matchuuid,
                        :total_amount,
                        :commision

                    )
                """),
                {
                    "uuid": commission_uuid,
                    "roomcode": match["roomcode"],
                    "matchuuid": matchuuid,
                    "total_amount": total_amount,
                    "commision": commission
                }
            )


            # =========================================
            # LOG MATCH COMPLETION
            # =========================================

            connection.execute(
                text("""
                    INSERT INTO admin_activity_logs (
                        uuid,
                        admin_username,
                        action,
                        description,
                        target_uuid,
                        target_type,
                        ip_address,
                        user_agent
                    )
                    VALUES (
                        :uuid,
                        :admin_username,
                        :action,
                        :description,
                        :target_uuid,
                        :target_type,
                        :ip_address,
                        :user_agent
                    )
                """),
                {
                    "uuid": str(uuid.uuid4()),

                    "admin_username":
                        session.get(
                            "admin_username",
                            ADMIN_USERNAME
                        ),

                    "action":
                        "MATCH_COMPLETED",

                    "description":
                        (
                            f"Match completed successfully. "
                            f"Winner: {winner_uuid}. "
                            f"Loser: {loser_uuid}. "
                            f"Amount: {amount}. "
                            f"Winner credit: {winner_amount}. "
                            f"Commission: {commission}. "
                            f"Room code: {match['roomcode']}."
                        ),

                    "target_uuid":
                        matchuuid,

                    "target_type":
                        "MATCH",

                    "ip_address":
                        request.remote_addr,

                    "user_agent":
                        request.headers.get(
                            "User-Agent",
                            ""
                        )
                }
            )


        flash(
            "Match completed successfully.",
            "success"
        )


    except Exception:

        flash(
            "Unable to complete the match.",
            "error"
        )


    return redirect(
        url_for("admin.admin_dashboard")
    )



# =====================================================
# SAVE ADMIN ACCOUNT DETAILS
# =====================================================

@admin_bp.route("/save-details", methods=["POST"])
def save_admin_details():

    try:

        if not session.get("admin_logged_in"):

            return redirect(
                url_for("admin.admin_login")
            )


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

        upiid = request.form.get(
            "upiid",
            ""
        ).strip()

        contact = request.form.get(
            "contact",
            ""
        ).strip()


        # ---------------------------------------------
        # CONTACT IS REQUIRED
        # ---------------------------------------------

        if not contact:

            flash(
                "Contact number is required.",
                "error"
            )

            return redirect(
                url_for("admin.admin_dashboard")
            )


        # ---------------------------------------------
        # CHECK BANK DETAILS
        # ---------------------------------------------

        bank_complete = (
            bool(bank_name)
            and bool(account_number)
            and bool(ifsc_code)
        )


        # ---------------------------------------------
        # CHECK UPI
        # ---------------------------------------------

        upi_complete = bool(upiid)


        # ---------------------------------------------
        # AT LEAST ONE PAYMENT METHOD REQUIRED
        # ---------------------------------------------

        if not bank_complete and not upi_complete:

            flash(
                "Please provide complete bank details or a UPI ID.",
                "error"
            )

            return redirect(
                url_for("admin.admin_dashboard")
            )


        # ---------------------------------------------
        # REJECT PARTIAL BANK DETAILS
        # ---------------------------------------------

        bank_fields_entered = (
            bool(bank_name)
            or bool(account_number)
            or bool(ifsc_code)
        )


        if bank_fields_entered and not bank_complete:

            flash(
                "Please provide Bank Name, Account Number and IFSC Code together.",
                "error"
            )

            return redirect(
                url_for("admin.admin_dashboard")
            )


        # ---------------------------------------------
        # SAVE DETAILS
        # ---------------------------------------------

        try:

            with db_engine.begin() as connection:

                existing_details = connection.execute(
                    text("""
                        SELECT 1
                        FROM adetails
                        LIMIT 1
                    """)
                ).first()


                if existing_details:

                    connection.execute(
                        text("""
                            UPDATE adetails
                            SET
                                bank_name = :bank_name,
                                account_number = :account_number,
                                ifsc_code = :ifsc_code,
                                upiid = :upiid,
                                contact = :contact
                        """),
                        {
                            "bank_name": bank_name or "Not Added",
                            "account_number": account_number or "Not Added",
                            "ifsc_code": ifsc_code or "Not Added",
                            "upiid": upiid or "Not Added",
                            "contact": contact
                        }
                    )

                    activity_description = (
                        "Admin account details updated."
                    )

                    activity_action = (
                        "ADMIN_DETAILS_UPDATED"
                    )

                else:

                    connection.execute(
                        text("""
                            INSERT INTO adetails (
                                bank_name,
                                account_number,
                                ifsc_code,
                                upiid,
                                contact
                            )
                            VALUES (
                                :bank_name,
                                :account_number,
                                :ifsc_code,
                                :upiid,
                                :contact
                            )
                        """),
                        {
                            "bank_name": bank_name or "Not Added",
                            "account_number": account_number or "Not Added",
                            "ifsc_code": ifsc_code or "Not Added",
                            "upiid": upiid or "Not Added",
                            "contact": contact
                        }
                    )

                    activity_description = (
                        "Admin account details added."
                    )

                    activity_action = (
                        "ADMIN_DETAILS_UPDATED"
                    )


                # =====================================
                # LOG ADMIN ACTIVITY
                # =====================================

                connection.execute(
                    text("""
                        INSERT INTO admin_activity_logs (
                            uuid,
                            admin_username,
                            action,
                            description,
                            target_uuid,
                            target_type,
                            ip_address,
                            user_agent
                        )
                        VALUES (
                            :uuid,
                            :admin_username,
                            :action,
                            :description,
                            :target_uuid,
                            :target_type,
                            :ip_address,
                            :user_agent
                        )
                    """),
                    {
                        "uuid": str(uuid.uuid4()),

                        "admin_username":
                            session.get(
                                "admin_username",
                                ADMIN_USERNAME
                            ),

                        "action":
                            activity_action,

                        "description":
                            activity_description,

                        "target_uuid":
                            "admin",

                        "target_type":
                            "ADMIN",

                        "ip_address":
                            request.remote_addr,

                        "user_agent":
                            request.headers.get(
                                "User-Agent",
                                ""
                            )
                    }
                )


            flash(
                "Account details updated successfully.",
                "success"
            )


        except Exception:

            # -----------------------------------------
            # LOG FAILED DATABASE OPERATION
            # -----------------------------------------

            try:

                with db_engine.begin() as connection:

                    connection.execute(
                        text("""
                            INSERT INTO admin_activity_logs (
                                uuid,
                                admin_username,
                                action,
                                description,
                                target_uuid,
                                target_type,
                                ip_address,
                                user_agent
                            )
                            VALUES (
                                :uuid,
                                :admin_username,
                                :action,
                                :description,
                                :target_uuid,
                                :target_type,
                                :ip_address,
                                :user_agent
                            )
                        """),
                        {
                            "uuid": str(uuid.uuid4()),

                            "admin_username":
                                session.get(
                                    "admin_username",
                                    ADMIN_USERNAME
                                ),

                            "action":
                                "ADMIN_DETAILS_UPDATE_FAILED",

                            "description":
                                "Admin account details update failed due to a database error.",

                            "target_uuid":
                                "admin",

                            "target_type":
                                "ADMIN",

                            "ip_address":
                                request.remote_addr,

                            "user_agent":
                                request.headers.get(
                                    "User-Agent",
                                    ""
                                )
                        }
                    )

            except Exception:
                pass


            flash(
                "Unable to save account details.",
                "error"
            )


        return redirect(
            url_for("admin.admin_dashboard")
        )


    except Exception:

        flash(
            "Something went wrong. Please try again.",
            "error"
        )

        return redirect(
            url_for("admin.admin_dashboard")
        )

# =====================================================
# USERS BALANCE
# =====================================================

@admin_bp.route("/users-balance")
def users_balance():

    try:

        if not session.get("admin_logged_in"):
            return redirect(
                url_for("admin.admin_login")
            )


        # ---------------------------------------------
        # PAGINATION
        # ---------------------------------------------

        page = request.args.get(
            "page",
            1,
            type=int
        )

        if page < 1:
            page = 1

        per_page = 10

        offset = (page - 1) * per_page


        with db_engine.connect() as connection:

            # -----------------------------------------
            # TOTAL PENDING PAYMENTS
            # -----------------------------------------

            total_payments = connection.execute(
                text("""
                    SELECT COUNT(*) AS total
                    FROM upaymentproof
                    WHERE status = 'pending'
                """)
            ).scalar()


            # -----------------------------------------
            # FETCH 10 PAYMENTS
            # -----------------------------------------

            payment_proofs = connection.execute(
                text("""
                    SELECT

                        p.user_uuid,

                        u.username,

                        p.amount,

                        p.date,

                        p.utr,

                        p.status

                    FROM upaymentproof p

                    INNER JOIN lpusers u
                        ON u.uuid = p.user_uuid

                    WHERE p.status = 'pending'

                    ORDER BY p.timestamp ASC

                    LIMIT :limit
                    OFFSET :offset

                """),
                {
                    "limit": per_page,
                    "offset": offset
                }
            ).mappings().all()


        # ---------------------------------------------
        # TOTAL PAGES
        # ---------------------------------------------

        total_pages = (
            (total_payments + per_page - 1)
            // per_page
        )


        # ---------------------------------------------
        # PREVENT INVALID PAGE
        # ---------------------------------------------

        if total_pages > 0 and page > total_pages:

            return redirect(
                url_for(
                    "admin.users_balance",
                    page=total_pages
                )
            )


        # ---------------------------------------------
        # LOG USERS BALANCE VIEW
        # ---------------------------------------------

        with db_engine.begin() as connection:

            connection.execute(
                text("""
                    INSERT INTO admin_activity_logs (
                        uuid,
                        admin_username,
                        action,
                        description,
                        target_uuid,
                        target_type,
                        ip_address,
                        user_agent
                    )
                    VALUES (
                        :uuid,
                        :admin_username,
                        :action,
                        :description,
                        :target_uuid,
                        :target_type,
                        :ip_address,
                        :user_agent
                    )
                """),
                {
                    "uuid": str(uuid.uuid4()),

                    "admin_username":
                        session.get(
                            "admin_username",
                            ADMIN_USERNAME
                        ),

                    "action":
                        "USERS_BALANCE_VIEW",

                    "description":
                        f"Admin viewed pending user balance payments. Page: {page}",

                    "target_uuid":
                        "admin",

                    "target_type":
                        "ADMIN",

                    "ip_address":
                        request.remote_addr,

                    "user_agent":
                        request.headers.get(
                            "User-Agent",
                            ""
                        )
                }
            )


        return render_template(
            "admin/users_balance.html",

            payment_proofs=payment_proofs,

            current_page=page,

            total_pages=total_pages
        )


    except Exception:

        flash(
            "Something went wrong. Please try again.",
            "error"
        )

        return redirect(
            url_for("admin.admin_dashboard")
        )


# =====================================================
# PROCESS USER BALANCE
# =====================================================

@admin_bp.route("/process-balance", methods=["POST"])
def process_balance():

    try:

        if not session.get("admin_logged_in"):

            return redirect(
                url_for("admin.admin_login")
            )


        proof_utr = request.form.get(
            "utr",
            ""
        ).strip()

        action = request.form.get(
            "action",
            ""
        ).strip().lower()


        if not proof_utr:

            flash(
                "Payment proof information is missing.",
                "error"
            )

            return redirect(
                url_for("admin.users_balance")
            )


        if action not in ("confirm", "reject"):

            flash(
                "Invalid action.",
                "error"
            )

            return redirect(
                url_for("admin.users_balance")
            )


        try:

            with db_engine.begin() as connection:

                # =========================================
                # LOCK PAYMENT PROOF
                # =========================================

                proof = connection.execute(
                    text("""
                        SELECT
                            user_uuid,
                            amount,
                            status
                        FROM upaymentproof
                        WHERE utr = :utr
                        LIMIT 1
                        FOR UPDATE
                    """),
                    {
                        "utr": proof_utr
                    }
                ).mappings().first()


                if not proof:

                    connection.execute(
                        text("""
                            INSERT INTO admin_activity_logs (
                                uuid,
                                admin_username,
                                action,
                                description,
                                target_uuid,
                                target_type,
                                ip_address,
                                user_agent
                            )
                            VALUES (
                                :uuid,
                                :admin_username,
                                :action,
                                :description,
                                :target_uuid,
                                :target_type,
                                :ip_address,
                                :user_agent
                            )
                        """),
                        {
                            "uuid": str(uuid.uuid4()),

                            "admin_username":
                                session.get(
                                    "admin_username",
                                    ADMIN_USERNAME
                                ),

                            "action":
                                "BALANCE_PROCESSING_FAILED",

                            "description":
                                "Admin attempted to process a payment proof that was not found.",

                            "target_uuid":
                                proof_utr,

                            "target_type":
                                "PAYMENT",

                            "ip_address":
                                request.remote_addr,

                            "user_agent":
                                request.headers.get(
                                    "User-Agent",
                                    ""
                                )
                        }
                    )

                    flash(
                        "Payment proof not found.",
                        "error"
                    )

                    return redirect(
                        url_for("admin.users_balance")
                    )


                # =========================================
                # ALREADY PROCESSED
                # =========================================

                if proof["status"] != "pending":

                    connection.execute(
                        text("""
                            INSERT INTO admin_activity_logs (
                                uuid,
                                admin_username,
                                action,
                                description,
                                target_uuid,
                                target_type,
                                ip_address,
                                user_agent
                            )
                            VALUES (
                                :uuid,
                                :admin_username,
                                :action,
                                :description,
                                :target_uuid,
                                :target_type,
                                :ip_address,
                                :user_agent
                            )
                        """),
                        {
                            "uuid": str(uuid.uuid4()),

                            "admin_username":
                                session.get(
                                    "admin_username",
                                    ADMIN_USERNAME
                                ),

                            "action":
                                "BALANCE_PROCESSING_FAILED",

                            "description":
                                "Admin attempted to process a payment proof that had already been processed.",

                            "target_uuid":
                                proof_utr,

                            "target_type":
                                "PAYMENT",

                            "ip_address":
                                request.remote_addr,

                            "user_agent":
                                request.headers.get(
                                    "User-Agent",
                                    ""
                                )
                        }
                    )

                    flash(
                        "This payment has already been processed.",
                        "error"
                    )

                    return redirect(
                        url_for("admin.users_balance")
                    )


                # =========================================
                # REJECT
                # =========================================

                if action == "reject":

                    connection.execute(
                        text("""
                            UPDATE upaymentproof

                            SET status = 'rejected'

                            WHERE utr = :utr
                        """),
                        {
                            "utr": proof_utr
                        }
                    )


                    # -------------------------------------
                    # LOG REJECTION
                    # -------------------------------------

                    connection.execute(
                        text("""
                            INSERT INTO admin_activity_logs (
                                uuid,
                                admin_username,
                                action,
                                description,
                                target_uuid,
                                target_type,
                                ip_address,
                                user_agent
                            )
                            VALUES (
                                :uuid,
                                :admin_username,
                                :action,
                                :description,
                                :target_uuid,
                                :target_type,
                                :ip_address,
                                :user_agent
                            )
                        """),
                        {
                            "uuid": str(uuid.uuid4()),

                            "admin_username":
                                session.get(
                                    "admin_username",
                                    ADMIN_USERNAME
                                ),

                            "action":
                                "BALANCE_REJECTED",

                            "description":
                                "Admin rejected a user balance payment proof.",

                            "target_uuid":
                                proof_utr,

                            "target_type":
                                "PAYMENT",

                            "ip_address":
                                request.remote_addr,

                            "user_agent":
                                request.headers.get(
                                    "User-Agent",
                                    ""
                                )
                        }
                    )


                    flash(
                        "Payment proof rejected.",
                        "success"
                    )

                    return redirect(
                        url_for("admin.users_balance")
                    )


                # =========================================
                # CONFIRM
                # =========================================

                if action == "confirm":

                    user = connection.execute(
                        text("""
                            SELECT uuid
                            FROM lpusers
                            WHERE uuid = :user_uuid
                            LIMIT 1
                            FOR UPDATE
                        """),
                        {
                            "user_uuid": proof["user_uuid"]
                        }
                    ).mappings().first()


                    if not user:

                        connection.execute(
                            text("""
                                INSERT INTO admin_activity_logs (
                                    uuid,
                                    admin_username,
                                    action,
                                    description,
                                    target_uuid,
                                    target_type,
                                    ip_address,
                                    user_agent
                                )
                                VALUES (
                                    :uuid,
                                    :admin_username,
                                    :action,
                                    :description,
                                    :target_uuid,
                                    :target_type,
                                    :ip_address,
                                    :user_agent
                                )
                            """),
                            {
                                "uuid": str(uuid.uuid4()),

                                "admin_username":
                                    session.get(
                                        "admin_username",
                                        ADMIN_USERNAME
                                    ),

                                "action":
                                    "BALANCE_PROCESSING_FAILED",

                                "description":
                                    "Admin attempted to confirm a payment proof, but the user account was not found.",

                                "target_uuid":
                                    proof_utr,

                                "target_type":
                                    "PAYMENT",

                                "ip_address":
                                    request.remote_addr,

                                "user_agent":
                                    request.headers.get(
                                        "User-Agent",
                                        ""
                                    )
                            }
                        )

                        flash(
                            "User account not found.",
                            "error"
                        )

                        return redirect(
                            url_for("admin.users_balance")
                        )


                    # -------------------------------------
                    # ADD MONEY TO USER ACCOUNT
                    # -------------------------------------

                    connection.execute(
                        text("""
                            UPDATE lpusers

                            SET money = money + :amount

                            WHERE uuid = :user_uuid
                        """),
                        {
                            "amount": proof["amount"],
                            "user_uuid": proof["user_uuid"]
                        }
                    )


                    # -------------------------------------
                    # CONFIRM PAYMENT
                    # -------------------------------------

                    connection.execute(
                        text("""
                            UPDATE upaymentproof

                            SET status = 'confirmed'

                            WHERE utr = :utr
                        """),
                        {
                            "utr": proof_utr
                        }
                    )


                    # -------------------------------------
                    # LOG CONFIRMATION
                    # -------------------------------------

                    connection.execute(
                        text("""
                            INSERT INTO admin_activity_logs (
                                uuid,
                                admin_username,
                                action,
                                description,
                                target_uuid,
                                target_type,
                                ip_address,
                                user_agent
                            )
                            VALUES (
                                :uuid,
                                :admin_username,
                                :action,
                                :description,
                                :target_uuid,
                                :target_type,
                                :ip_address,
                                :user_agent
                            )
                        """),
                        {
                            "uuid": str(uuid.uuid4()),

                            "admin_username":
                                session.get(
                                    "admin_username",
                                    ADMIN_USERNAME
                                ),

                            "action":
                                "BALANCE_CONFIRMED",

                            "description":
                                "Admin confirmed a user balance payment and credited the user account.",

                            "target_uuid":
                                proof_utr,

                            "target_type":
                                "PAYMENT",

                            "ip_address":
                                request.remote_addr,

                            "user_agent":
                                request.headers.get(
                                    "User-Agent",
                                    ""
                                )
                        }
                    )


                    flash(
                        "Balance added successfully.",
                        "success"
                    )


        except Exception:

            # -----------------------------------------
            # LOG PROCESSING FAILURE
            # -----------------------------------------

            try:

                with db_engine.begin() as connection:

                    connection.execute(
                        text("""
                            INSERT INTO admin_activity_logs (
                                uuid,
                                admin_username,
                                action,
                                description,
                                target_uuid,
                                target_type,
                                ip_address,
                                user_agent
                            )
                            VALUES (
                                :uuid,
                                :admin_username,
                                :action,
                                :description,
                                :target_uuid,
                                :target_type,
                                :ip_address,
                                :user_agent
                            )
                        """),
                        {
                            "uuid": str(uuid.uuid4()),

                            "admin_username":
                                session.get(
                                    "admin_username",
                                    ADMIN_USERNAME
                                ),

                            "action":
                                "BALANCE_PROCESSING_FAILED",

                            "description":
                                "Admin payment proof processing failed due to a database or transaction error.",

                            "target_uuid":
                                proof_utr or "unknown",

                            "target_type":
                                "PAYMENT",

                            "ip_address":
                                request.remote_addr,

                            "user_agent":
                                request.headers.get(
                                    "User-Agent",
                                    ""
                                )
                        }
                    )

            except Exception:
                pass


            flash(
                "Unable to process payment proof.",
                "error"
            )


        return redirect(
            url_for("admin.users_balance")
        )


    except Exception:

        flash(
            "Something went wrong. Please try again.",
            "error"
        )

        return redirect(
            url_for("admin.users_balance")
        )


@admin_bp.route("/users-withdrawals")
def users_withdrawals():

    try:

        if not session.get("admin_logged_in"):
            return redirect(url_for("admin.admin_login"))

        # ---------------------------------------------
        # PAGINATION
        # ---------------------------------------------

        page = request.args.get("page", 1, type=int)

        if page < 1:
            page = 1

        per_page = 10

        offset = (page - 1) * per_page


        with db_engine.connect() as connection:

            # -----------------------------------------
            # TOTAL PENDING WITHDRAWALS
            # -----------------------------------------

            total_withdrawals = connection.execute(
                text("""
                    SELECT COUNT(*) AS total
                    FROM withdrawal_requests
                    WHERE status = 'pending'
                """)
            ).scalar()


            # -----------------------------------------
            # FETCH 10 WITHDRAWALS
            # -----------------------------------------

            withdrawal_requests = connection.execute(
                text("""
                    SELECT
                        w.uuid,
                        w.user_uuid,
                        u.username,
                        w.amount,
                        w.medium,
                        w.timestamp,
                        d.bank_name,
                        d.account_number,
                        d.ifsc_code,
                        d.upi_id

                    FROM withdrawal_requests w

                    INNER JOIN lpusers u
                        ON u.uuid = w.user_uuid

                    LEFT JOIN udetails d
                        ON d.user_uuid = w.user_uuid

                    WHERE w.status = 'pending'

                    ORDER BY w.timestamp ASC

                    LIMIT :limit
                    OFFSET :offset
                """),
                {
                    "limit": per_page,
                    "offset": offset
                }
            ).mappings().all()


        # ---------------------------------------------
        # TOTAL PAGES
        # ---------------------------------------------

        total_pages = (
            (total_withdrawals + per_page - 1)
            // per_page
        )


        # ---------------------------------------------
        # PREVENT INVALID PAGE
        # ---------------------------------------------

        if total_pages > 0 and page > total_pages:

            return redirect(
                url_for(
                    "admin.users_withdrawals",
                    page=total_pages
                )
            )


        # ---------------------------------------------
        # LOG WITHDRAWALS PAGE VIEW
        # ---------------------------------------------

        with db_engine.begin() as connection:

            connection.execute(
                text("""
                    INSERT INTO admin_activity_logs (
                        uuid,
                        admin_username,
                        action,
                        description,
                        target_uuid,
                        target_type,
                        ip_address,
                        user_agent
                    )
                    VALUES (
                        :uuid,
                        :admin_username,
                        :action,
                        :description,
                        :target_uuid,
                        :target_type,
                        :ip_address,
                        :user_agent
                    )
                """),
                {
                    "uuid": str(uuid.uuid4()),

                    "admin_username":
                        session.get(
                            "admin_username",
                            ADMIN_USERNAME
                        ),

                    "action":
                        "USERS_WITHDRAWALS_VIEW",

                    "description":
                        f"Admin viewed pending user withdrawal requests. Page: {page}",

                    "target_uuid":
                        "admin",

                    "target_type":
                        "ADMIN",

                    "ip_address":
                        request.remote_addr,

                    "user_agent":
                        request.headers.get(
                            "User-Agent",
                            ""
                        )
                }
            )


        return render_template(
            "admin/users_withdrawals.html",

            withdrawal_requests=withdrawal_requests,

            current_page=page,

            total_pages=total_pages
        )


    except Exception:

        flash(
            "Something went wrong. Please try again.",
            "error"
        )

        return redirect(
            url_for("admin.admin_dashboard")
        )


@admin_bp.route("/process-withdrawal", methods=["POST"])
def process_withdrawal():

    try:

        if not session.get("admin_logged_in"):
            return redirect(url_for("admin.admin_login"))

        withdrawal_uuid = request.form.get(
            "withdrawal_uuid",
            ""
        ).strip()

        action = request.form.get(
            "action",
            ""
        ).strip().lower()

        if not withdrawal_uuid:

            flash(
                "Withdrawal request information is missing.",
                "error"
            )

            return redirect(
                url_for("admin.users_withdrawals")
            )

        if action not in ("completed", "rejected"):

            flash(
                "Invalid action.",
                "error"
            )

            return redirect(
                url_for("admin.users_withdrawals")
            )

        try:

            with db_engine.begin() as connection:

                # ---------------------------------------------
                # LOCK WITHDRAWAL REQUEST
                # ---------------------------------------------

                withdrawal = connection.execute(
                    text("""
                        SELECT
                            uuid,
                            user_uuid,
                            amount,
                            status
                        FROM withdrawal_requests
                        WHERE uuid = :withdrawal_uuid
                        LIMIT 1
                        FOR UPDATE
                    """),
                    {
                        "withdrawal_uuid": withdrawal_uuid
                    }
                ).mappings().first()

                if not withdrawal:

                    connection.execute(
                        text("""
                            INSERT INTO admin_activity_logs (
                                uuid,
                                admin_username,
                                action,
                                description,
                                target_uuid,
                                target_type,
                                ip_address,
                                user_agent
                            )
                            VALUES (
                                :uuid,
                                :admin_username,
                                :action,
                                :description,
                                :target_uuid,
                                :target_type,
                                :ip_address,
                                :user_agent
                            )
                        """),
                        {
                            "uuid": str(uuid.uuid4()),

                            "admin_username":
                                session.get(
                                    "admin_username",
                                    ADMIN_USERNAME
                                ),

                            "action":
                                "WITHDRAWAL_PROCESSING_FAILED",

                            "description":
                                "Admin attempted to process a withdrawal request that was not found.",

                            "target_uuid":
                                withdrawal_uuid,

                            "target_type":
                                "WITHDRAWAL",

                            "ip_address":
                                request.remote_addr,

                            "user_agent":
                                request.headers.get(
                                    "User-Agent",
                                    ""
                                )
                        }
                    )

                    flash(
                        "Withdrawal request not found.",
                        "error"
                    )

                    return redirect(
                        url_for("admin.users_withdrawals")
                    )


                # ---------------------------------------------
                # ALREADY PROCESSED
                # ---------------------------------------------

                if withdrawal["status"] != "pending":

                    connection.execute(
                        text("""
                            INSERT INTO admin_activity_logs (
                                uuid,
                                admin_username,
                                action,
                                description,
                                target_uuid,
                                target_type,
                                ip_address,
                                user_agent
                            )
                            VALUES (
                                :uuid,
                                :admin_username,
                                :action,
                                :description,
                                :target_uuid,
                                :target_type,
                                :ip_address,
                                :user_agent
                            )
                        """),
                        {
                            "uuid": str(uuid.uuid4()),

                            "admin_username":
                                session.get(
                                    "admin_username",
                                    ADMIN_USERNAME
                                ),

                            "action":
                                "WITHDRAWAL_PROCESSING_FAILED",

                            "description":
                                "Admin attempted to process a withdrawal request that had already been processed.",

                            "target_uuid":
                                withdrawal_uuid,

                            "target_type":
                                "WITHDRAWAL",

                            "ip_address":
                                request.remote_addr,

                            "user_agent":
                                request.headers.get(
                                    "User-Agent",
                                    ""
                                )
                        }
                    )

                    flash(
                        "This withdrawal has already been processed.",
                        "error"
                    )

                    return redirect(
                        url_for("admin.users_withdrawals")
                    )


                # ---------------------------------------------
                # REJECT
                # ---------------------------------------------

                if action == "rejected":

                    connection.execute(
                        text("""
                            UPDATE withdrawal_requests
                            SET status = 'rejected'
                            WHERE uuid = :withdrawal_uuid
                        """),
                        {
                            "withdrawal_uuid": withdrawal_uuid
                        }
                    )


                    # -----------------------------------------
                    # LOG REJECTION
                    # -----------------------------------------

                    connection.execute(
                        text("""
                            INSERT INTO admin_activity_logs (
                                uuid,
                                admin_username,
                                action,
                                description,
                                target_uuid,
                                target_type,
                                ip_address,
                                user_agent
                            )
                            VALUES (
                                :uuid,
                                :admin_username,
                                :action,
                                :description,
                                :target_uuid,
                                :target_type,
                                :ip_address,
                                :user_agent
                            )
                        """),
                        {
                            "uuid": str(uuid.uuid4()),

                            "admin_username":
                                session.get(
                                    "admin_username",
                                    ADMIN_USERNAME
                                ),

                            "action":
                                "WITHDRAWAL_REJECTED",

                            "description":
                                "Admin rejected a user withdrawal request.",

                            "target_uuid":
                                withdrawal_uuid,

                            "target_type":
                                "WITHDRAWAL",

                            "ip_address":
                                request.remote_addr,

                            "user_agent":
                                request.headers.get(
                                    "User-Agent",
                                    ""
                                )
                        }
                    )


                    flash(
                        "Withdrawal request rejected.",
                        "success"
                    )

                    return redirect(
                        url_for("admin.users_withdrawals")
                    )


                # ---------------------------------------------
                # LOCK USER
                # ---------------------------------------------

                user = connection.execute(
                    text("""
                        SELECT
                            uuid,
                            money
                        FROM lpusers
                        WHERE uuid = :user_uuid
                        LIMIT 1
                        FOR UPDATE
                    """),
                    {
                        "user_uuid": withdrawal["user_uuid"]
                    }
                ).mappings().first()


                if not user:

                    connection.execute(
                        text("""
                            INSERT INTO admin_activity_logs (
                                uuid,
                                admin_username,
                                action,
                                description,
                                target_uuid,
                                target_type,
                                ip_address,
                                user_agent
                            )
                            VALUES (
                                :uuid,
                                :admin_username,
                                :action,
                                :description,
                                :target_uuid,
                                :target_type,
                                :ip_address,
                                :user_agent
                            )
                        """),
                        {
                            "uuid": str(uuid.uuid4()),

                            "admin_username":
                                session.get(
                                    "admin_username",
                                    ADMIN_USERNAME
                                ),

                            "action":
                                "WITHDRAWAL_PROCESSING_FAILED",

                            "description":
                                "Admin attempted to complete a withdrawal, but the user account was not found.",

                            "target_uuid":
                                withdrawal_uuid,

                            "target_type":
                                "WITHDRAWAL",

                            "ip_address":
                                request.remote_addr,

                            "user_agent":
                                request.headers.get(
                                    "User-Agent",
                                    ""
                                )
                        }
                    )

                    flash(
                        "User account not found.",
                        "error"
                    )

                    return redirect(
                        url_for("admin.users_withdrawals")
                    )


                # ---------------------------------------------
                # CHECK BALANCE
                # ---------------------------------------------

                if user["money"] < withdrawal["amount"]:

                    connection.execute(
                        text("""
                            INSERT INTO admin_activity_logs (
                                uuid,
                                admin_username,
                                action,
                                description,
                                target_uuid,
                                target_type,
                                ip_address,
                                user_agent
                            )
                            VALUES (
                                :uuid,
                                :admin_username,
                                :action,
                                :description,
                                :target_uuid,
                                :target_type,
                                :ip_address,
                                :user_agent
                            )
                        """),
                        {
                            "uuid": str(uuid.uuid4()),

                            "admin_username":
                                session.get(
                                    "admin_username",
                                    ADMIN_USERNAME
                                ),

                            "action":
                                "WITHDRAWAL_PROCESSING_FAILED",

                            "description":
                                "Admin attempted to complete a withdrawal, but the user did not have sufficient balance.",

                            "target_uuid":
                                withdrawal_uuid,

                            "target_type":
                                "WITHDRAWAL",

                            "ip_address":
                                request.remote_addr,

                            "user_agent":
                                request.headers.get(
                                    "User-Agent",
                                    ""
                                )
                        }
                    )

                    flash(
                        "User does not have sufficient balance.",
                        "error"
                    )

                    return redirect(
                        url_for("admin.users_withdrawals")
                    )


                # ---------------------------------------------
                # DEDUCT MONEY
                # ---------------------------------------------

                connection.execute(
                    text("""
                        UPDATE lpusers
                        SET money = money - :amount
                        WHERE uuid = :user_uuid
                    """),
                    {
                        "amount": withdrawal["amount"],
                        "user_uuid": withdrawal["user_uuid"]
                    }
                )


                # ---------------------------------------------
                # MARK COMPLETED
                # ---------------------------------------------

                connection.execute(
                    text("""
                        UPDATE withdrawal_requests
                        SET status = 'completed'
                        WHERE uuid = :withdrawal_uuid
                    """),
                    {
                        "withdrawal_uuid": withdrawal_uuid
                    }
                )


                # ---------------------------------------------
                # LOG COMPLETION
                # ---------------------------------------------

                connection.execute(
                    text("""
                        INSERT INTO admin_activity_logs (
                            uuid,
                            admin_username,
                            action,
                            description,
                            target_uuid,
                            target_type,
                            ip_address,
                            user_agent
                        )
                        VALUES (
                            :uuid,
                            :admin_username,
                            :action,
                            :description,
                            :target_uuid,
                            :target_type,
                            :ip_address,
                            :user_agent
                        )
                    """),
                    {
                        "uuid": str(uuid.uuid4()),

                        "admin_username":
                            session.get(
                                "admin_username",
                                ADMIN_USERNAME
                            ),

                        "action":
                            "WITHDRAWAL_COMPLETED",

                        "description":
                            "Admin completed a user withdrawal request and deducted the withdrawal amount from the user balance.",

                        "target_uuid":
                            withdrawal_uuid,

                        "target_type":
                            "WITHDRAWAL",

                        "ip_address":
                            request.remote_addr,

                        "user_agent":
                            request.headers.get(
                                "User-Agent",
                                ""
                            )
                    }
                )


                flash(
                    "Withdrawal completed successfully.",
                    "success"
                )


        except Exception:

            # -----------------------------------------
            # LOG PROCESSING FAILURE
            # -----------------------------------------

            try:

                with db_engine.begin() as connection:

                    connection.execute(
                        text("""
                            INSERT INTO admin_activity_logs (
                                uuid,
                                admin_username,
                                action,
                                description,
                                target_uuid,
                                target_type,
                                ip_address,
                                user_agent
                            )
                            VALUES (
                                :uuid,
                                :admin_username,
                                :action,
                                :description,
                                :target_uuid,
                                :target_type,
                                :ip_address,
                                :user_agent
                            )
                        """),
                        {
                            "uuid": str(uuid.uuid4()),

                            "admin_username":
                                session.get(
                                    "admin_username",
                                    ADMIN_USERNAME
                                ),

                            "action":
                                "WITHDRAWAL_PROCESSING_FAILED",

                            "description":
                                "Admin withdrawal processing failed due to a database or transaction error.",

                            "target_uuid":
                                withdrawal_uuid or "unknown",

                            "target_type":
                                "WITHDRAWAL",

                            "ip_address":
                                request.remote_addr,

                            "user_agent":
                                request.headers.get(
                                    "User-Agent",
                                    ""
                                )
                        }
                    )

            except Exception:
                pass


            flash(
                "Unable to process withdrawal request.",
                "error"
            )


        return redirect(
            url_for("admin.users_withdrawals")
        )


    except Exception:

        flash(
            "Something went wrong. Please try again.",
            "error"
        )

        return redirect(
            url_for("admin.users_withdrawals")
        )

@admin_bp.route("/block-users")
def block_users():

    try:

        if not session.get("admin_logged_in"):

            return redirect(
                url_for("admin.admin_login")
            )


        # ---------------------------------------------
        # SEARCH USERNAME
        # ---------------------------------------------

        username_search = request.args.get(
            "username",
            ""
        ).strip()


        # ---------------------------------------------
        # STATUS FILTER
        # ---------------------------------------------

        status_filter = request.args.get(
            "status",
            ""
        ).strip().lower()


        if status_filter not in (
            "",
            "active",
            "inactive"
        ):

            status_filter = ""


        # ---------------------------------------------
        # PAGINATION
        # ---------------------------------------------

        page = request.args.get(
            "page",
            1,
            type=int
        )


        if page < 1:

            page = 1


        # ---------------------------------------------
        # PAGE SIZE
        # ---------------------------------------------

        if username_search or status_filter:

            per_page = 5

        else:

            per_page = 10


        offset = (page - 1) * per_page


        # ---------------------------------------------
        # STATUS VALUE
        # ---------------------------------------------

        status_value = None

        if status_filter == "active":

            status_value = 1

        elif status_filter == "inactive":

            status_value = 0


        with db_engine.connect() as connection:

            # =========================================
            # TOTAL USERS
            # =========================================

            total_users = connection.execute(
                text("""
                    SELECT COUNT(*) AS total

                    FROM lpusers

                    WHERE
                        (
                            :username_search = ''
                            OR username LIKE :username_pattern
                        )

                        AND

                        (
                            :status_value IS NULL
                            OR status = :status_value
                        )
                """),
                {
                    "username_search":
                        username_search,

                    "username_pattern":
                        f"%{username_search}%",

                    "status_value":
                        status_value
                }
            ).scalar()


            # =========================================
            # FETCH USERS
            # =========================================

            users = connection.execute(
                text("""
                    SELECT
                        uuid,
                        username,
                        status

                    FROM lpusers

                    WHERE
                        (
                            :username_search = ''
                            OR username LIKE :username_pattern
                        )

                        AND

                        (
                            :status_value IS NULL
                            OR status = :status_value
                        )

                    ORDER BY timestamp DESC

                    LIMIT :limit
                    OFFSET :offset
                """),
                {
                    "username_search":
                        username_search,

                    "username_pattern":
                        f"%{username_search}%",

                    "status_value":
                        status_value,

                    "limit":
                        per_page,

                    "offset":
                        offset
                }
            ).mappings().all()


        # ---------------------------------------------
        # TOTAL PAGES
        # ---------------------------------------------

        total_pages = (
            (total_users + per_page - 1)
            // per_page
        )


        # ---------------------------------------------
        # PREVENT INVALID PAGE
        # ---------------------------------------------

        if total_pages > 0 and page > total_pages:

            return redirect(
                url_for(
                    "admin.block_users",
                    page=total_pages,
                    username=username_search,
                    status=status_filter
                )
            )


        # ---------------------------------------------
        # LOG PAGE VIEW
        # ---------------------------------------------

        with db_engine.begin() as connection:

            connection.execute(
                text("""
                    INSERT INTO admin_activity_logs (
                        uuid,
                        admin_username,
                        action,
                        description,
                        target_uuid,
                        target_type,
                        ip_address,
                        user_agent
                    )
                    VALUES (
                        :uuid,
                        :admin_username,
                        :action,
                        :description,
                        :target_uuid,
                        :target_type,
                        :ip_address,
                        :user_agent
                    )
                """),
                {
                    "uuid":
                        str(uuid.uuid4()),

                    "admin_username":
                        session.get(
                            "admin_username",
                            ADMIN_USERNAME
                        ),

                    "action":
                        "BLOCK_USERS_VIEW",

                    "description":
                        (
                            "Admin viewed the block users page. "
                            f"Page: {page}. "
                            f"Username search: "
                            f"{username_search or 'None'}. "
                            f"Status filter: "
                            f"{status_filter or 'All'}."
                        ),

                    "target_uuid":
                        "admin",

                    "target_type":
                        "ADMIN",

                    "ip_address":
                        request.remote_addr,

                    "user_agent":
                        request.headers.get(
                            "User-Agent",
                            ""
                        )
                }
            )


        return render_template(
            "admin/block_users.html",

            users=users,

            current_page=page,

            total_pages=total_pages,

            username_search=username_search,

            status_filter=status_filter
        )


    except Exception:

        flash(
            "Something went wrong. Please try again.",
            "error"
        )

        return redirect(
            url_for("admin.admin_dashboard")
        )


@admin_bp.route("/change-user-status", methods=["POST"])
def change_user_status():

    try:

        # ---------------------------------------------
        # CHECK ADMIN LOGIN
        # ---------------------------------------------

        if not session.get("admin_logged_in"):

            return redirect(
                url_for("admin.admin_login")
            )


        # ---------------------------------------------
        # GET FORM DATA
        # ---------------------------------------------

        user_uuid = request.form.get(
            "user_uuid",
            ""
        ).strip()

        new_status = request.form.get(
            "new_status",
            ""
        ).strip()

        status_password = request.form.get(
            "status_password",
            ""
        )


        # ---------------------------------------------
        # BASIC VALIDATION
        # ---------------------------------------------

        if not user_uuid:

            flash(
                "User information is missing.",
                "error"
            )

            return redirect(
                url_for("admin.block_users")
            )


        if new_status not in ("0", "1"):

            flash(
                "Invalid user status.",
                "error"
            )

            return redirect(
                url_for("admin.block_users")
            )


        if not status_password:

            flash(
                "Password is required.",
                "error"
            )

            return redirect(
                url_for("admin.block_users")
            )


        # ---------------------------------------------
        # CHECK STATUS PASSWORD
        # ---------------------------------------------

        if status_password != STATUS_PASSWORD:

            # -----------------------------------------
            # LOG INVALID PASSWORD
            # -----------------------------------------

            try:

                with db_engine.begin() as connection:

                    connection.execute(
                        text("""
                            INSERT INTO admin_activity_logs (
                                uuid,
                                admin_username,
                                action,
                                description,
                                target_uuid,
                                target_type,
                                ip_address,
                                user_agent
                            )
                            VALUES (
                                :uuid,
                                :admin_username,
                                :action,
                                :description,
                                :target_uuid,
                                :target_type,
                                :ip_address,
                                :user_agent
                            )
                        """),
                        {
                            "uuid": str(uuid.uuid4()),

                            "admin_username":
                                session.get(
                                    "admin_username",
                                    ADMIN_USERNAME
                                ),

                            "action":
                                "USER_STATUS_PASSWORD_FAILED",

                            "description":
                                (
                                    "Admin attempted to change "
                                    "user status with an invalid "
                                    "status password."
                                ),

                            "target_uuid":
                                user_uuid,

                            "target_type":
                                "USER",

                            "ip_address":
                                request.remote_addr,

                            "user_agent":
                                request.headers.get(
                                    "User-Agent",
                                    ""
                                )
                        }
                    )

            except Exception:
                pass


            flash(
                "Invalid password. User status didn't change.",
                "error"
            )

            return redirect(
                url_for("admin.block_users")
            )


        # ---------------------------------------------
        # CHANGE USER STATUS
        # ---------------------------------------------

        try:

            with db_engine.begin() as connection:

                # =====================================
                # LOCK USER
                # =====================================

                user = connection.execute(
                    text("""
                        SELECT
                            uuid,
                            username,
                            status
                        FROM lpusers
                        WHERE uuid = :user_uuid
                        LIMIT 1
                        FOR UPDATE
                    """),
                    {
                        "user_uuid": user_uuid
                    }
                ).mappings().first()


                # =====================================
                # USER NOT FOUND
                # =====================================

                if not user:

                    connection.execute(
                        text("""
                            INSERT INTO admin_activity_logs (
                                uuid,
                                admin_username,
                                action,
                                description,
                                target_uuid,
                                target_type,
                                ip_address,
                                user_agent
                            )
                            VALUES (
                                :uuid,
                                :admin_username,
                                :action,
                                :description,
                                :target_uuid,
                                :target_type,
                                :ip_address,
                                :user_agent
                            )
                        """),
                        {
                            "uuid": str(uuid.uuid4()),

                            "admin_username":
                                session.get(
                                    "admin_username",
                                    ADMIN_USERNAME
                                ),

                            "action":
                                "USER_STATUS_CHANGE_FAILED",

                            "description":
                                "Admin attempted to change the status of a user that was not found.",

                            "target_uuid":
                                user_uuid,

                            "target_type":
                                "USER",

                            "ip_address":
                                request.remote_addr,

                            "user_agent":
                                request.headers.get(
                                    "User-Agent",
                                    ""
                                )
                        }
                    )

                    flash(
                        "User not found.",
                        "error"
                    )

                    return redirect(
                        url_for("admin.block_users")
                    )


                # =====================================
                # CURRENT STATUS
                # =====================================

                current_status = int(
                    user["status"]
                )

                requested_status = int(
                    new_status
                )


                # =====================================
                # STATUS ALREADY SAME
                # =====================================

                if current_status == requested_status:

                    connection.execute(
                        text("""
                            INSERT INTO admin_activity_logs (
                                uuid,
                                admin_username,
                                action,
                                description,
                                target_uuid,
                                target_type,
                                ip_address,
                                user_agent
                            )
                            VALUES (
                                :uuid,
                                :admin_username,
                                :action,
                                :description,
                                :target_uuid,
                                :target_type,
                                :ip_address,
                                :user_agent
                            )
                        """),
                        {
                            "uuid": str(uuid.uuid4()),

                            "admin_username":
                                session.get(
                                    "admin_username",
                                    ADMIN_USERNAME
                                ),

                            "action":
                                "USER_STATUS_CHANGE_FAILED",

                            "description":
                                (
                                    f"Admin attempted to change "
                                    f"the status of user "
                                    f"{user['username']}, but "
                                    f"the requested status was "
                                    f"already set."
                                ),

                            "target_uuid":
                                user_uuid,

                            "target_type":
                                "USER",

                            "ip_address":
                                request.remote_addr,

                            "user_agent":
                                request.headers.get(
                                    "User-Agent",
                                    ""
                                )
                        }
                    )

                    flash(
                        "User already has this status.",
                        "error"
                    )

                    return redirect(
                        url_for("admin.block_users")
                    )


                # =====================================
                # CHANGE STATUS
                # =====================================

                connection.execute(
                    text("""
                        UPDATE lpusers

                        SET status = :new_status

                        WHERE uuid = :user_uuid
                    """),
                    {
                        "new_status":
                            requested_status,

                        "user_uuid":
                            user_uuid
                    }
                )


                # =====================================
                # DETERMINE ACTIVITY
                # =====================================

                if requested_status == 0:

                    activity_action = (
                        "USER_DEACTIVATED"
                    )

                    activity_description = (
                        f"Admin deactivated user "
                        f"{user['username']}."
                    )

                else:

                    activity_action = (
                        "USER_ACTIVATED"
                    )

                    activity_description = (
                        f"Admin activated user "
                        f"{user['username']}."
                    )


                # =====================================
                # LOG STATUS CHANGE
                # =====================================

                connection.execute(
                    text("""
                        INSERT INTO admin_activity_logs (
                            uuid,
                            admin_username,
                            action,
                            description,
                            target_uuid,
                            target_type,
                            ip_address,
                            user_agent
                        )
                        VALUES (
                            :uuid,
                            :admin_username,
                            :action,
                            :description,
                            :target_uuid,
                            :target_type,
                            :ip_address,
                            :user_agent
                        )
                    """),
                    {
                        "uuid": str(uuid.uuid4()),

                        "admin_username":
                            session.get(
                                "admin_username",
                                ADMIN_USERNAME
                            ),

                        "action":
                            activity_action,

                        "description":
                            activity_description,

                        "target_uuid":
                            user_uuid,

                        "target_type":
                            "USER",

                        "ip_address":
                            request.remote_addr,

                        "user_agent":
                            request.headers.get(
                                "User-Agent",
                                ""
                            )
                    }
                )


            # =========================================
            # SUCCESS MESSAGE
            # =========================================

            if requested_status == 0:

                flash(
                    "User status changed successfully. User is now inactive.",
                    "success"
                )

            else:

                flash(
                    "User status changed successfully. User is now active.",
                    "success"
                )


        except Exception:

            # -----------------------------------------
            # LOG DATABASE / TRANSACTION FAILURE
            # -----------------------------------------

            try:

                with db_engine.begin() as connection:

                    connection.execute(
                        text("""
                            INSERT INTO admin_activity_logs (
                                uuid,
                                admin_username,
                                action,
                                description,
                                target_uuid,
                                target_type,
                                ip_address,
                                user_agent
                            )
                            VALUES (
                                :uuid,
                                :admin_username,
                                :action,
                                :description,
                                :target_uuid,
                                :target_type,
                                :ip_address,
                                :user_agent
                            )
                        """),
                        {
                            "uuid": str(uuid.uuid4()),

                            "admin_username":
                                session.get(
                                    "admin_username",
                                    ADMIN_USERNAME
                                ),

                            "action":
                                "USER_STATUS_CHANGE_FAILED",

                            "description":
                                "Admin user status change failed due to a database or transaction error.",

                            "target_uuid":
                                user_uuid,

                            "target_type":
                                "USER",

                            "ip_address":
                                request.remote_addr,

                            "user_agent":
                                request.headers.get(
                                    "User-Agent",
                                    ""
                                )
                        }
                    )

            except Exception:
                pass


            flash(
                "Unable to change user status.",
                "error"
            )


        return redirect(
            url_for("admin.block_users")
        )


    except Exception:

        flash(
            "Something went wrong. Please try again.",
            "error"
        )

        return redirect(
            url_for("admin.block_users")
        )

# =====================================================
# COMMISSION PAGE
# =====================================================

@admin_bp.route(
    "/commission",
    methods=["GET", "POST"]
)
def commission():

    try:

        # ---------------------------------------------
        # CHECK ADMIN LOGIN
        # ---------------------------------------------

        if not session.get("admin_logged_in"):

            return redirect(
                url_for(
                    "admin.admin_login"
                )
            )


        # Genuine admin activity

        session["admin_last_activity"] = time.time()


        # =============================================
        # INTERNAL PASSWORD
        # =============================================

        if request.method == "POST":


            internal_password = request.form.get(
                "internal_password",
                ""
            )


            # -----------------------------------------
            # PASSWORD CHECK
            # -----------------------------------------

            if internal_password != ADMININTERNAL:


                # -------------------------------------
                # LOG FAILED PASSWORD
                # -------------------------------------

                try:

                    with db_engine.begin() as connection:

                        connection.execute(
                            text("""
                                INSERT INTO admin_activity_logs (
                                    uuid,
                                    admin_username,
                                    action,
                                    description,
                                    target_uuid,
                                    target_type,
                                    ip_address,
                                    user_agent
                                )

                                VALUES (
                                    :uuid,
                                    :admin_username,
                                    :action,
                                    :description,
                                    :target_uuid,
                                    :target_type,
                                    :ip_address,
                                    :user_agent
                                )
                            """),
                            {

                                "uuid":
                                    str(uuid.uuid4()),

                                "admin_username":
                                    session.get(
                                        "admin_username",
                                        ADMIN_USERNAME
                                    ),

                                "action":
                                    "COMMISSION_PASSWORD_FAILED",

                                "description":
                                    "Admin attempted to access the commission page with an invalid internal password.",

                                "target_uuid":
                                    "admin",

                                "target_type":
                                    "ADMIN",

                                "ip_address":
                                    request.remote_addr,

                                "user_agent":
                                    request.headers.get(
                                        "User-Agent",
                                        ""
                                    )
                            }
                        )

                except Exception:

                    pass


                flash(
                    "Invalid password. Commission page access denied.",
                    "error"
                )


                return render_template(
                    "admin/commission_access.html"
                )


            # -----------------------------------------
            # PASSWORD CORRECT
            # -----------------------------------------

            session[
                "admin_commission_access"
            ] = True


            # -----------------------------------------
            # LOG SUCCESSFUL ACCESS
            # -----------------------------------------

            try:

                with db_engine.begin() as connection:

                    connection.execute(
                        text("""
                            INSERT INTO admin_activity_logs (
                                uuid,
                                admin_username,
                                action,
                                description,
                                target_uuid,
                                target_type,
                                ip_address,
                                user_agent
                            )

                            VALUES (
                                :uuid,
                                :admin_username,
                                :action,
                                :description,
                                :target_uuid,
                                :target_type,
                                :ip_address,
                                :user_agent
                            )
                        """),
                        {

                            "uuid":
                                str(uuid.uuid4()),

                            "admin_username":
                                session.get(
                                    "admin_username",
                                    ADMIN_USERNAME
                                ),

                            "action":
                                "COMMISSION_ACCESS_GRANTED",

                            "description":
                                "Admin successfully entered the internal commission password.",

                            "target_uuid":
                                "admin",

                            "target_type":
                                "ADMIN",

                            "ip_address":
                                request.remote_addr,

                            "user_agent":
                                request.headers.get(
                                    "User-Agent",
                                    ""
                                )
                        }
                    )

            except Exception:

                pass


            return redirect(
                url_for(
                    "admin.commission"
                )
            )


        # =============================================
        # BACKEND SECURITY CHECK
        # =============================================

        if not session.get(
            "admin_commission_access"
        ):

            return render_template(
                "admin/commission_access.html"
            )


        # =============================================
        # SEARCH
        # =============================================

        search_query = str(
            request.args.get(
                "search",
                ""
            )
        ).strip()


        # =============================================
        # PAGINATION
        # =============================================

        page_input = request.args.get(
            "page",
            "1"
        ).strip()


        try:

            page = int(
                page_input
            )

        except ValueError:

            page = 1


        if page < 1:

            page = 1


        # =============================================
        # RECORDS PER PAGE
        # =============================================

        if search_query:

            per_page = 7

        else:

            per_page = 10


        offset = (
            page - 1
        ) * per_page


        # =============================================
        # SEARCH PATTERN
        # =============================================

        search_pattern = (
            f"%{search_query}%"
        )


        # =============================================
        # GET COMMISSION DATA
        # =============================================

        with db_engine.connect() as connection:


            # -----------------------------------------
            # TOTAL RECORDS
            # -----------------------------------------

            total_records = connection.execute(
                text("""
                    SELECT COUNT(*) AS total

                    FROM acommission

                    WHERE
                        (
                            :search_query = ''

                            OR roomcode LIKE :search_pattern

                            OR CAST(
                                total_amount
                                AS CHAR
                            ) LIKE :search_pattern

                            OR CAST(
                                commision
                                AS CHAR
                            ) LIKE :search_pattern

                            OR DATE_FORMAT(
                                timestamp,
                                '%Y-%m-%d'
                            ) LIKE :search_pattern

                            OR DATE_FORMAT(
                                timestamp,
                                '%d-%m-%Y'
                            ) LIKE :search_pattern
                        )
                """),
                {

                    "search_query":
                        search_query,

                    "search_pattern":
                        search_pattern
                }
            ).scalar()


            # -----------------------------------------
            # FETCH RECORDS
            # -----------------------------------------

            commission_records = connection.execute(
                text("""
                    SELECT

                        uuid,

                        roomcode,

                        matchuuid,

                        total_amount,

                        commision,

                        timestamp

                    FROM acommission

                    WHERE
                        (
                            :search_query = ''

                            OR roomcode LIKE :search_pattern

                            OR CAST(
                                total_amount
                                AS CHAR
                            ) LIKE :search_pattern

                            OR CAST(
                                commision
                                AS CHAR
                            ) LIKE :search_pattern

                            OR DATE_FORMAT(
                                timestamp,
                                '%Y-%m-%d'
                            ) LIKE :search_pattern

                            OR DATE_FORMAT(
                                timestamp,
                                '%d-%m-%Y'
                            ) LIKE :search_pattern
                        )

                    ORDER BY timestamp DESC

                    LIMIT :limit

                    OFFSET :offset
                """),
                {

                    "search_query":
                        search_query,

                    "search_pattern":
                        search_pattern,

                    "limit":
                        per_page,

                    "offset":
                        offset
                }
            ).mappings().all()


        # =============================================
        # TOTAL PAGES
        # =============================================

        total_pages = (
            total_records
            + per_page
            - 1
        ) // per_page


        # =============================================
        # INVALID PAGE
        # =============================================

        if (
            total_pages > 0
            and page > total_pages
        ):

            return redirect(
                url_for(
                    "admin.commission",
                    page=total_pages,
                    search=search_query
                )
            )


        # =============================================
        # LOG COMMISSION PAGE VIEW
        # =============================================

        try:

            with db_engine.begin() as connection:

                connection.execute(
                    text("""
                        INSERT INTO admin_activity_logs (
                            uuid,
                            admin_username,
                            action,
                            description,
                            target_uuid,
                            target_type,
                            ip_address,
                            user_agent
                        )

                        VALUES (
                            :uuid,
                            :admin_username,
                            :action,
                            :description,
                            :target_uuid,
                            :target_type,
                            :ip_address,
                            :user_agent
                        )
                    """),
                    {

                        "uuid":
                            str(uuid.uuid4()),

                        "admin_username":
                            session.get(
                                "admin_username",
                                ADMIN_USERNAME
                            ),

                        "action":
                            "COMMISSION_VIEW",

                        "description":
                            (
                                "Admin viewed the commission page. "
                                f"Page: {page}. "
                                f"Search: {search_query or 'None'}."
                            ),

                        "target_uuid":
                            "admin",

                        "target_type":
                            "ADMIN",

                        "ip_address":
                            request.remote_addr,

                        "user_agent":
                            request.headers.get(
                                "User-Agent",
                                ""
                            )
                    }
                )

        except Exception:

            pass


        # =============================================
        # RENDER
        # =============================================

        return render_template(
            "admin/commission.html",

            commission_records=
                commission_records,

            current_page=
                page,

            total_pages=
                total_pages,

            search_query=
                search_query
        )


    except Exception:

        flash(
            "Unable to load the commission page. Please try again.",
            "error"
        )

        return redirect(
            url_for(
                "admin.admin_dashboard"
            )
        )

# =====================================================
# ADMIN HISTORY
# =====================================================

@admin_bp.route(
    "/history",
    methods=["GET", "POST"]
)
def admin_history():

    try:

        # ---------------------------------------------
        # CHECK ADMIN LOGIN
        # ---------------------------------------------

        if not session.get("admin_logged_in"):

            return redirect(
                url_for(
                    "admin.admin_login"
                )
            )


        # Genuine admin activity

        session["admin_last_activity"] = time.time()


        # =============================================
        # INTERNAL PASSWORD
        # =============================================

        if request.method == "POST":

            internal_password = request.form.get(
                "internal_password",
                ""
            )


            # -----------------------------------------
            # PASSWORD CHECK
            # -----------------------------------------

            if internal_password != ADMININTERNAL:

                # -------------------------------------
                # LOG FAILED PASSWORD
                # -------------------------------------

                try:

                    with db_engine.begin() as connection:

                        connection.execute(
                            text("""
                                INSERT INTO admin_activity_logs (
                                    uuid,
                                    admin_username,
                                    action,
                                    description,
                                    target_uuid,
                                    target_type,
                                    ip_address,
                                    user_agent
                                )
                                VALUES (
                                    :uuid,
                                    :admin_username,
                                    :action,
                                    :description,
                                    :target_uuid,
                                    :target_type,
                                    :ip_address,
                                    :user_agent
                                )
                            """),
                            {

                                "uuid":
                                    str(uuid.uuid4()),

                                "admin_username":
                                    session.get(
                                        "admin_username",
                                        ADMIN_USERNAME
                                    ),

                                "action":
                                    "ADMIN_HISTORY_PASSWORD_FAILED",

                                "description":
                                    "Admin attempted to access the admin history page with an invalid internal password.",

                                "target_uuid":
                                    "admin",

                                "target_type":
                                    "ADMIN",

                                "ip_address":
                                    request.remote_addr,

                                "user_agent":
                                    request.headers.get(
                                        "User-Agent",
                                        ""
                                    )
                            }
                        )

                except Exception:

                    pass


                flash(
                    "Invalid password. Admin history access denied.",
                    "error"
                )

                return render_template(
                    "admin/history_access.html"
                )


            # -----------------------------------------
            # PASSWORD CORRECT
            # -----------------------------------------

            session[
                "admin_history_access"
            ] = True


            # -----------------------------------------
            # LOG SUCCESSFUL ACCESS
            # -----------------------------------------

            try:

                with db_engine.begin() as connection:

                    connection.execute(
                        text("""
                            INSERT INTO admin_activity_logs (
                                uuid,
                                admin_username,
                                action,
                                description,
                                target_uuid,
                                target_type,
                                ip_address,
                                user_agent
                            )
                            VALUES (
                                :uuid,
                                :admin_username,
                                :action,
                                :description,
                                :target_uuid,
                                :target_type,
                                :ip_address,
                                :user_agent
                            )
                        """),
                        {

                            "uuid":
                                str(uuid.uuid4()),

                            "admin_username":
                                session.get(
                                    "admin_username",
                                    ADMIN_USERNAME
                                ),

                            "action":
                                "ADMIN_HISTORY_ACCESS_GRANTED",

                            "description":
                                "Admin successfully entered the internal password for admin history.",

                            "target_uuid":
                                "admin",

                            "target_type":
                                "ADMIN",

                            "ip_address":
                                request.remote_addr,

                            "user_agent":
                                request.headers.get(
                                    "User-Agent",
                                    ""
                                )
                        }
                    )

            except Exception:

                pass


            return redirect(
                url_for(
                    "admin.admin_history"
                )
            )


        # =============================================
        # BACKEND SECURITY CHECK
        # =============================================

        if not session.get(
            "admin_history_access"
        ):

            return render_template(
                "admin/history_access.html"
            )


        # =============================================
        # SEARCH
        # =============================================

        search_query = str(
            request.args.get(
                "search",
                ""
            )
        ).strip()


        # =============================================
        # PAGINATION
        # =============================================

        page_input = request.args.get(
            "page",
            "1"
        ).strip()


        try:

            page = int(
                page_input
            )

        except ValueError:

            page = 1


        if page < 1:

            page = 1


        # =============================================
        # RECORDS PER PAGE
        # =============================================

        if search_query:

            per_page = 10

        else:

            per_page = 15


        offset = (
            page - 1
        ) * per_page


        # =============================================
        # SEARCH PATTERN
        # =============================================

        search_pattern = (
            f"%{search_query}%"
        )


        # =============================================
        # GET ADMIN HISTORY
        # =============================================

        with db_engine.connect() as connection:


            # -----------------------------------------
            # TOTAL RECORDS
            # -----------------------------------------

            total_records = connection.execute(
                text("""
                    SELECT COUNT(*) AS total

                    FROM admin_activity_logs

                    WHERE
                        (
                            :search_query = ''

                            OR DATE_FORMAT(
                                timestamp,
                                '%Y-%m-%d'
                            ) LIKE :search_pattern

                            OR DATE_FORMAT(
                                timestamp,
                                '%d-%m-%Y'
                            ) LIKE :search_pattern

                            OR DATE_FORMAT(
                                timestamp,
                                '%H:%i:%s'
                            ) LIKE :search_pattern
                        )
                """),
                {

                    "search_query":
                        search_query,

                    "search_pattern":
                        search_pattern
                }
            ).scalar()


            # -----------------------------------------
            # FETCH HISTORY
            # -----------------------------------------

            history_records = connection.execute(
                text("""
                    SELECT

                        admin_username,

                        action,

                        description,

                        target_type,

                        ip_address,

                        user_agent,

                        timestamp

                    FROM admin_activity_logs

                    WHERE
                        (
                            :search_query = ''

                            OR DATE_FORMAT(
                                timestamp,
                                '%Y-%m-%d'
                            ) LIKE :search_pattern

                            OR DATE_FORMAT(
                                timestamp,
                                '%d-%m-%Y'
                            ) LIKE :search_pattern

                            OR DATE_FORMAT(
                                timestamp,
                                '%H:%i:%s'
                            ) LIKE :search_pattern
                        )

                    ORDER BY
                        timestamp DESC

                    LIMIT :limit

                    OFFSET :offset
                """),
                {

                    "search_query":
                        search_query,

                    "search_pattern":
                        search_pattern,

                    "limit":
                        per_page,

                    "offset":
                        offset
                }
            ).mappings().all()


        # =============================================
        # TOTAL PAGES
        # =============================================

        total_pages = (
            total_records
            + per_page
            - 1
        ) // per_page


        # =============================================
        # INVALID PAGE
        # =============================================

        if (
            total_pages > 0
            and page > total_pages
        ):

            return redirect(
                url_for(
                    "admin.admin_history",
                    page=total_pages,
                    search=search_query
                )
            )


        # =============================================
        # LOG HISTORY PAGE VIEW
        # =============================================

        
        return render_template(
         "admin/admin_history.html",
          history_records=history_records,
          total_records=total_records,
          current_page=page,
          total_pages=total_pages,
          search_query=search_query
        )

    except Exception:

        flash(
            "Unable to load the admin history page. Please try again.",
            "error"
        )

        return redirect(
            url_for(
                "admin.admin_dashboard"
            )
        )

# =====================================================
# TOTAL MONEY CREDITED
# =====================================================

@admin_bp.route(
    "/total-money-credited",
    methods=["GET"]
)
def total_money_credited():

    try:

        # ---------------------------------------------
        # CHECK ADMIN LOGIN
        # ---------------------------------------------

        if not session.get("admin_logged_in"):

            return redirect(
                url_for("admin.admin_login")
            )


        # ---------------------------------------------
        # UPDATE ADMIN ACTIVITY
        # ---------------------------------------------

        session["admin_last_activity"] = time.time()


        # ---------------------------------------------
        # SEARCH
        # ---------------------------------------------

        search_query = str(
            request.args.get(
                "search",
                ""
            )
        ).strip()


        # ---------------------------------------------
        # PAGE
        # ---------------------------------------------

        page_input = request.args.get(
            "page",
            "1"
        ).strip()


        try:

            page = int(page_input)

        except ValueError:

            page = 1


        if page < 1:

            page = 1


        # ---------------------------------------------
        # PAGINATION
        # ---------------------------------------------

        per_page = 15

        offset = (
            page - 1
        ) * per_page


        search_pattern = (
            f"%{search_query}%"
        )


        # ---------------------------------------------
        # DATABASE
        # ---------------------------------------------

        with db_engine.connect() as connection:


            # =========================================
            # TOTAL CONFIRMED AMOUNT
            # =========================================

            total_amount_credited = connection.execute(
                text("""
                    SELECT
                        COALESCE(
                            SUM(amount),
                            0
                        )
                    FROM upaymentproof
                    WHERE status = 'confirm'
                """)
            ).scalar()


            # =========================================
            # TOTAL RECORDS
            # =========================================

            total_records = connection.execute(
                text("""
                    SELECT
                        COUNT(*)
                    FROM upaymentproof up

                    LEFT JOIN lpusers u
                        ON u.uuid = up.user_uuid

                    WHERE
                        :search_query = ''

                        OR u.username LIKE :search_pattern

                        OR up.utr LIKE :search_pattern

                        OR CAST(
                            up.amount
                            AS CHAR
                        ) LIKE :search_pattern

                        OR DATE_FORMAT(
                            up.date,
                            '%Y-%m-%d'
                        ) LIKE :search_pattern

                        OR DATE_FORMAT(
                            up.date,
                            '%d-%m-%Y'
                        ) LIKE :search_pattern

                        OR DATE_FORMAT(
                            up.timestamp,
                            '%Y-%m-%d'
                        ) LIKE :search_pattern

                        OR DATE_FORMAT(
                            up.timestamp,
                            '%d-%m-%Y'
                        ) LIKE :search_pattern

                        OR DATE_FORMAT(
                            up.timestamp,
                            '%H:%i:%s'
                        ) LIKE :search_pattern
                """),
                {
                    "search_query": search_query,
                    "search_pattern": search_pattern
                }
            ).scalar()


            # =========================================
            # PAYMENT RECORDS
            # =========================================

            payment_records = connection.execute(
                text("""
                    SELECT

                        u.username,

                        up.amount,

                        up.utr,

                        up.status,

                        up.date,

                        up.timestamp

                    FROM upaymentproof up

                    LEFT JOIN lpusers u
                        ON u.uuid = up.user_uuid

                    WHERE
                        :search_query = ''

                        OR u.username LIKE :search_pattern

                        OR up.utr LIKE :search_pattern

                        OR CAST(
                            up.amount
                            AS CHAR
                        ) LIKE :search_pattern

                        OR DATE_FORMAT(
                            up.date,
                            '%Y-%m-%d'
                        ) LIKE :search_pattern

                        OR DATE_FORMAT(
                            up.date,
                            '%d-%m-%Y'
                        ) LIKE :search_pattern

                        OR DATE_FORMAT(
                            up.timestamp,
                            '%Y-%m-%d'
                        ) LIKE :search_pattern

                        OR DATE_FORMAT(
                            up.timestamp,
                            '%d-%m-%Y'
                        ) LIKE :search_pattern

                        OR DATE_FORMAT(
                            up.timestamp,
                            '%H:%i:%s'
                        ) LIKE :search_pattern

                    ORDER BY
                        up.timestamp DESC

                    LIMIT :limit
                    OFFSET :offset
                """),
                {
                    "search_query": search_query,
                    "search_pattern": search_pattern,
                    "limit": per_page,
                    "offset": offset
                }
            ).mappings().all()


        # ---------------------------------------------
        # TOTAL PAGES
        # ---------------------------------------------

        total_pages = (
            total_records
            + per_page
            - 1
        ) // per_page


        # ---------------------------------------------
        # INVALID PAGE
        # ---------------------------------------------

        if (
            total_pages > 0
            and page > total_pages
        ):

            return redirect(
                url_for(
                    "admin.total_money_credited",
                    page=total_pages,
                    search=search_query
                )
            )


        # ---------------------------------------------
        # RENDER
        # ---------------------------------------------

        return render_template(
            "admin/total_money_credited.html",

            payment_records=payment_records,

            total_amount_credited=total_amount_credited,

            total_records=total_records,

            current_page=page,

            total_pages=total_pages,

            search_query=search_query
        )


    except Exception:

        flash(
            "Unable to load the total money credited page. Please try again.",
            "error"
        )

        return redirect(
            url_for(
                "admin.admin_dashboard"
            )
        )


# =====================================================
# TOTAL DEBITS
# =====================================================

@admin_bp.route(
    "/total-debits",
    methods=["GET"]
)
def total_debits():

    try:

        # ---------------------------------------------
        # CHECK ADMIN LOGIN
        # ---------------------------------------------

        if not session.get("admin_logged_in"):

            return redirect(
                url_for("admin.admin_login")
            )


        # ---------------------------------------------
        # UPDATE ADMIN ACTIVITY
        # ---------------------------------------------

        session["admin_last_activity"] = time.time()


        # ---------------------------------------------
        # SEARCH
        # ---------------------------------------------

        search_query = str(
            request.args.get(
                "search",
                ""
            )
        ).strip()


        # ---------------------------------------------
        # PAGE
        # ---------------------------------------------

        page_input = request.args.get(
            "page",
            "1"
        ).strip()


        try:

            page = int(page_input)

        except ValueError:

            page = 1


        if page < 1:

            page = 1


        # ---------------------------------------------
        # PAGINATION
        # ---------------------------------------------

        per_page = 15

        offset = (
            page - 1
        ) * per_page


        search_pattern = (
            f"%{search_query}%"
        )


        # ---------------------------------------------
        # DATABASE
        # ---------------------------------------------

        with db_engine.connect() as connection:


            # =========================================
            # TOTAL DEBITED AMOUNT
            # =========================================

            total_amount_debited = connection.execute(
                text("""
                    SELECT
                        COALESCE(
                            SUM(amount),
                            0
                        )
                    FROM withdrawal_requests
                    WHERE status = 'completed'
                """)
            ).scalar()


            # =========================================
            # TOTAL RECORDS
            # =========================================

            total_records = connection.execute(
                text("""
                    SELECT
                        COUNT(*)
                    FROM withdrawal_requests wr

                    LEFT JOIN lpusers u
                        ON u.uuid = wr.user_uuid

                    WHERE
                        wr.status = 'completed'

                        AND (
                            :search_query = ''

                            OR u.username LIKE :search_pattern

                            OR CAST(
                                wr.amount
                                AS CHAR
                            ) LIKE :search_pattern

                            OR wr.medium LIKE :search_pattern

                            OR DATE_FORMAT(
                                wr.timestamp,
                                '%Y-%m-%d'
                            ) LIKE :search_pattern

                            OR DATE_FORMAT(
                                wr.timestamp,
                                '%d-%m-%Y'
                            ) LIKE :search_pattern

                            OR DATE_FORMAT(
                                wr.timestamp,
                                '%H:%i:%s'
                            ) LIKE :search_pattern
                        )
                """),
                {
                    "search_query": search_query,
                    "search_pattern": search_pattern
                }
            ).scalar()


            # =========================================
            # DEBIT RECORDS
            # =========================================

            debit_records = connection.execute(
                text("""
                    SELECT

                        u.username,

                        wr.amount,

                        wr.medium,

                        wr.status,

                        wr.timestamp

                    FROM withdrawal_requests wr

                    LEFT JOIN lpusers u
                        ON u.uuid = wr.user_uuid

                    WHERE
                        wr.status = 'completed'

                        AND (
                            :search_query = ''

                            OR u.username LIKE :search_pattern

                            OR CAST(
                                wr.amount
                                AS CHAR
                            ) LIKE :search_pattern

                            OR wr.medium LIKE :search_pattern

                            OR DATE_FORMAT(
                                wr.timestamp,
                                '%Y-%m-%d'
                            ) LIKE :search_pattern

                            OR DATE_FORMAT(
                                wr.timestamp,
                                '%d-%m-%Y'
                            ) LIKE :search_pattern

                            OR DATE_FORMAT(
                                wr.timestamp,
                                '%H:%i:%s'
                            ) LIKE :search_pattern
                        )

                    ORDER BY
                        wr.timestamp DESC

                    LIMIT :limit
                    OFFSET :offset
                """),
                {
                    "search_query": search_query,
                    "search_pattern": search_pattern,
                    "limit": per_page,
                    "offset": offset
                }
            ).mappings().all()


        # ---------------------------------------------
        # TOTAL PAGES
        # ---------------------------------------------

        total_pages = (
            total_records
            + per_page
            - 1
        ) // per_page


        # ---------------------------------------------
        # INVALID PAGE
        # ---------------------------------------------

        if (
            total_pages > 0
            and page > total_pages
        ):

            return redirect(
                url_for(
                    "admin.total_debits",
                    page=total_pages,
                    search=search_query
                )
            )


        # ---------------------------------------------
        # RENDER
        # ---------------------------------------------

        return render_template(
            "admin/total_debits.html",

            debit_records=debit_records,

            total_amount_debited=total_amount_debited,

            total_records=total_records,

            current_page=page,

            total_pages=total_pages,

            search_query=search_query
        )


    except Exception:

        flash(
            "Unable to load the total debits page. Please try again.",
            "error"
        )

        return redirect(
            url_for(
                "admin.admin_dashboard"
            )
        )
