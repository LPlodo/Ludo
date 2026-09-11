import os

from dotenv import load_dotenv
from sqlalchemy import create_engine, text


# =====================================================
# LOAD ENVIRONMENT VARIABLES
# =====================================================

load_dotenv()


# =====================================================
# DATABASE CONFIGURATION
# =====================================================

DB_HOST = os.environ["MYSQLHOST"]

DB_PORT = os.environ.get(
    "MYSQLPORT",
    "3306"
)

DB_USER = os.environ["MYSQLUSER"]

DB_PASSWORD = os.environ["MYSQLPASSWORD"]

DB_NAME = os.environ["MYSQLDATABASE"]


# =====================================================
# MYSQL SERVER ENGINE
# Used to create the database
# =====================================================

SERVER_URL = (
    f"mysql+pymysql://"
    f"{DB_USER}:{DB_PASSWORD}"
    f"@{DB_HOST}:{DB_PORT}"
)


server_engine = create_engine(
    SERVER_URL,
    pool_pre_ping=True
)


# =====================================================
# APPLICATION DATABASE URL
# =====================================================

DATABASE_URL = (
    f"mysql+pymysql://"
    f"{DB_USER}:{DB_PASSWORD}"
    f"@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)

# =====================================================
# DATABASE INITIALIZATION
# =====================================================

def initialize_database():

    # -------------------------------------------------
    # STEP 1: CREATE DATABASE IF NOT EXISTS
    # -------------------------------------------------

    with server_engine.connect() as connection:

        connection.execute(
            text(
                f"""
                CREATE DATABASE IF NOT EXISTS `{DB_NAME}`
                """
            )
        )

        connection.commit()


    # -------------------------------------------------
    # STEP 2: CREATE SQLALCHEMY ENGINE / DB POOL
    # -------------------------------------------------

    db_engine = create_engine(

        DATABASE_URL,

        pool_size=10,
        max_overflow=20,

        pool_pre_ping=True,
        pool_recycle=3600

    )


    # -------------------------------------------------
    # STEP 3: CREATE TABLES IF NOT EXISTS
    # -------------------------------------------------

    with db_engine.connect() as connection:

        # =============================================
        # LPUSERS TABLE
        # =============================================

        connection.execute(
            text(
                 """
                CREATE TABLE IF NOT EXISTS lpusers (

                    uuid CHAR(36) NOT NULL,

                    username VARCHAR(100) NOT NULL UNIQUE,
       
                     phone_number VARCHAR(20) NOT NULL,

                         password VARCHAR(255) NOT NULL,
      
                    money DECIMAL(15, 2)
                           NOT NULL DEFAULT 0.00,
      
                         status BOOLEAN
                         NOT NULL DEFAULT TRUE,
 
                     timestamp TIMESTAMP
                         NOT NULL DEFAULT CURRENT_TIMESTAMP,

                      PRIMARY KEY (uuid)

                )
                """
            )
        )

       
        connection.execute(
          text(
               """
             CREATE TABLE IF NOT EXISTS umatches (

            uuid CHAR(36) NOT NULL,

            match_initiated_by CHAR(36) NOT NULL,

            timestamp TIMESTAMP NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            amount BIGINT NOT NULL,

            roomcode VARCHAR(255) NOT NULL UNIQUE,

            match_attendedby CHAR(36) NULL,

            atimestamp TIMESTAMP NULL,

            status VARCHAR(20) NOT NULL
                DEFAULT 'active',

            is_terminated BOOLEAN NOT NULL
                DEFAULT FALSE,

            PRIMARY KEY (uuid),

            CONSTRAINT fk_umatches_initiator
                FOREIGN KEY (match_initiated_by)
                REFERENCES lpusers(uuid),

            CONSTRAINT fk_umatches_attendee
                FOREIGN KEY (match_attendedby)
                REFERENCES lpusers(uuid)

               )
               """
           )
        )
       
       
        connection.execute(
           text(
              """
             CREATE TABLE IF NOT EXISTS adetails (

            bank_name VARCHAR(255) NOT NULL
                DEFAULT 'Not Added',

            account_number VARCHAR(255) NOT NULL
                DEFAULT 'Not Added',

            ifsc_code VARCHAR(255) NOT NULL
                DEFAULT 'Not Added',

            upiid VARCHAR(255) NOT NULL
                DEFAULT 'Not Added',

            contact VARCHAR(255) NOT NULL
                DEFAULT 'Not Added'

             )
              """
         )
        )

        connection.execute(
            text(
               """
           CREATE TABLE IF NOT EXISTS uresults (

            matchuuid CHAR(36) NOT NULL,

            user1uuid CHAR(36) NOT NULL,

            user1option VARCHAR(20) NULL,

            user2uuid CHAR(36) NULL,

            user2option VARCHAR(20) NULL,

            winner CHAR(36) NULL,

            status VARCHAR(20) NOT NULL
                DEFAULT 'hold',

            remark TEXT NULL

               )
             """
            )
        )

       
        connection.execute(
    text("""
        CREATE TABLE IF NOT EXISTS upaymentproof (
            user_uuid CHAR(36) NOT NULL,
            date DATE NOT NULL,
            amount DECIMAL(15, 2) NOT NULL,
            utr VARCHAR(255) NOT NULL UNIQUE,
            status VARCHAR(20) NOT NULL DEFAULT 'pending',
            timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

            CONSTRAINT fk_upaymentproof_user
                FOREIGN KEY (user_uuid)
                REFERENCES lpusers(uuid)
              )
          """)
        )


        connection.execute(
          text("""
           CREATE TABLE IF NOT EXISTS udetails (
            user_uuid CHAR(36) NOT NULL,
            bank_name VARCHAR(255) NOT NULL DEFAULT 'Not Added',
            account_number VARCHAR(255) NOT NULL DEFAULT 'Not Added',
            ifsc_code VARCHAR(255) NOT NULL DEFAULT 'Not Added',
            upi_id VARCHAR(255) NOT NULL DEFAULT 'Not Added',

            CONSTRAINT fk_udetails_user
                FOREIGN KEY (user_uuid)
                REFERENCES lpusers(uuid)
            )
        """)
        )

        connection.execute(
         text("""
        CREATE TABLE IF NOT EXISTS withdrawal_requests (
            uuid CHAR(36) NOT NULL,
            user_uuid CHAR(36) NOT NULL,
            amount DECIMAL(15, 2) NOT NULL,
            medium VARCHAR(20) NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'pending',
            timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

            PRIMARY KEY (uuid),

            CONSTRAINT fk_withdrawal_requests_user
                FOREIGN KEY (user_uuid)
                REFERENCES lpusers(uuid)
             )
         """)
        )


               # =============================================
        # ACOMMISSION TABLE
        # =============================================

        connection.execute(
            text("""
                CREATE TABLE IF NOT EXISTS acommission (

                    uuid CHAR(36) NOT NULL,

                    roomcode VARCHAR(255) NOT NULL,

                    matchuuid CHAR(36) NOT NULL,

                    total_amount DECIMAL(15, 2) NOT NULL,

                    commision DECIMAL(15, 2) NOT NULL,

                    timestamp TIMESTAMP NOT NULL
                        DEFAULT CURRENT_TIMESTAMP,

                    PRIMARY KEY (uuid)

                )
            """)
        )

        connection.execute(text("""
             CREATE TABLE IF NOT EXISTS admin_activity_logs (

              uuid CHAR(36) NOT NULL,

              admin_username VARCHAR(100) NOT NULL,

              action VARCHAR(100) NOT NULL,

              description TEXT NULL,

              target_uuid CHAR(36) NULL,

              target_type VARCHAR(50) NULL,

              ip_address VARCHAR(45) NULL,

              user_agent TEXT NULL,

              timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

               PRIMARY KEY (uuid)

        )"""))


        
        # -------------------------------------------------
        # COMMIT TABLE CREATION
        # -------------------------------------------------

        connection.commit()


    # -------------------------------------------------
    # RETURN DATABASE ENGINE / POOL
    # -------------------------------------------------

    return db_engine
