const { promisePool } = require("../config/mysqlDB");
const { v4: uuidv4 } = require("uuid");

const login = async (userId, password) => {
    try {
        console.log(`Login attempt for userId: ${userId}`, `Login attempt for password: ${password}`);

        // Fetch user details
        const userQuery = `
        SELECT ua.lock_status, ua.account_status, ua.pass_expiry_dt, ua.first_time_login, ua.last_login_date, ua.failed_login_attempts, 
        CAST(ua.password AS CHAR) AS password, ua.user_role, ud.user_type, ud.job_title, ud.emp_type FROM userAuthInfo ua 
        JOIN userDetails ud ON ua.user_id = ud.user_id WHERE ua.user_id = ?; `;
        
        console.log(`Executing Query: ${userQuery.replace('?', `"${userId}"`)}`);
        const [userRows] = await promisePool.execute(userQuery, [userId]);

        if (userRows.length === 0) {
            console.log(`Invalid user ID: ${userId}`);
            await updateFailedAttempts(userId);
            return `UserNotFound: ${userId}`;
        }

        let user = userRows[0];
        console.log(`Retrieved user data: `, user);
        
        const currentDateTime = new Date();

        // Fetch ConfigurableItems for lockout settings
        const configQuery = `
            SELECT field_name, field_value FROM ConfigurableItems 
            WHERE field_name IN ('Account lockout threshold', 'Unlock account')
        `;
        
        console.log(`Executing Query: ${configQuery}`);
        const [configRows] = await promisePool.execute(configQuery);

        const config = Object.fromEntries(configRows.map(row => [row.field_name, row.field_value]));
        const lockoutThreshold = parseInt(config["Account lockout threshold"].split(" ")[0]);
        const unlockTime = parseInt(config["Unlock account"].split(" ")[0]);

        console.log(`Lockout Threshold: ${lockoutThreshold}, Unlock Time: ${unlockTime} hours`);

        // **1. Check if Account is Locked**
        if (user.lock_status === "Lock") {
            const lastFailedLogin = new Date(user.last_login_date);
            const timeDiff = (currentDateTime - lastFailedLogin) / (1000 * 60 * 60);

            if (timeDiff < unlockTime) {
                console.log(`Account locked for userId: ${userId}, remaining lock time: ${unlockTime - timeDiff} hours`);
                return "AccountLocked";
            } else {
                console.log(`Account unlocked after timeout for userId: ${userId}`);
                const unlockQuery = `UPDATE userAuthInfo SET lock_status = 'Unlock', failed_login_attempts = 0 WHERE user_id = ?`;
                console.log(`Executing Query: ${unlockQuery.replace('?', `"${userId}"`)}`);
                await promisePool.execute(unlockQuery, [userId]);
                user.lock_status = "Unlock";
            }
        }

        // **2. Account Status Check**
        if (user.account_status !== "Active") {
            console.log(`Account inactive for userId: ${userId}`);
            await updateFailedAttempts(userId, lockoutThreshold);
            return "AccountInactive";
        }

        // **3. Password Expiry Check**
        if (new Date(user.pass_expiry_dt) <= currentDateTime) {
            console.log(`Password expired for userId: ${userId}`);
            await updateFailedAttempts(userId, lockoutThreshold);
            return "PasswordExpired";
        }

        // **4. First-Time Login Check**
        if (user.first_time_login === "1") {
            console.log(`First-time login detected for userId: ${userId}. Reset required.`);
            await updateFailedAttempts(userId, lockoutThreshold);
            return "ResetPasswordRequired";
        }

        // **5. Password Validation**
        if (password !== user.password.toString()) {
            console.log(`Invalid password attempt for userId : ${userId}`);
            await updateFailedAttempts(userId, lockoutThreshold);

            // **Re-fetch user data to check if the account is now locked**
            const checkLockQuery = `SELECT lock_status FROM userAuthInfo WHERE user_id = ?`;
            console.log(`Executing Query: ${checkLockQuery.replace('?', `"${userId}"`)}`);
            const [updatedUserRows] = await promisePool.execute(checkLockQuery, [userId]);

            if (updatedUserRows.length > 0 && updatedUserRows[0].lock_status === "Lock") {
                console.log(`Account locked due to too many failed attempts for userId: ${userId}`);
                return "AccountLocked";
            }

            return "InvalidPassword";
        }

        // **6. Successful Login**
        const sessionId = uuidv4();
        console.log(`Login successful for userId: ${userId}. Session ID: ${sessionId}`);

        // const updateLoginQuery = `
        //     UPDATE userAuthInfo SET failed_login_attempts = 0, last_login_date = ?, session_id = ? WHERE user_id = ?
        // `;
        const updateLoginQuery = `
            UPDATE userAuthInfo 
            SET failed_login_attempts = 0, last_login_date = ?, session_id = ?,
                first_time_login = CASE WHEN first_time_login = '0' THEN '1' ELSE first_time_login END
            WHERE user_id = ?
        `;

        console.log(`Executing Query: ${updateLoginQuery.replace('?', `"${userId}"`)}`);
        await promisePool.execute(updateLoginQuery, [currentDateTime, sessionId, userId]);

        return { status: "success", 
            message: "Login successful.", 
            session_id: sessionId, 
            user_role: user.user_role,
            user_type: user.user_type,
            job_title: user.job_title,
            emp_type: user.emp_type
        };

    } 
    catch (error) {
      console.error(`Exception in login process for userId:`, error.message);

      if (error.code && error.code.startsWith('ER_')) {
          console.error("Database error occurred in login service");
          return 'DatabaseError';
      }

      console.error("An Internal server error occurred in login service");
      return 'InternalServerError';
  }
};

// **Helper function to update failed login attempts**
const updateFailedAttempts = async (userId, lockoutThreshold = null) => {
  try {
    const [userRows] = await promisePool.execute(
      `SELECT failed_login_attempts FROM userAuthInfo WHERE user_id = ?`,
      [userId]
    );

    if (userRows.length === 0) return;

    let failedAttempts = parseInt(userRows[0].failed_login_attempts || "0") + 1;
    let updateQuery = `UPDATE userAuthInfo SET failed_login_attempts = ?, last_failed_login_dt = ? WHERE user_id = ?`;
    let updateParams = [failedAttempts, new Date(), userId];

    if (lockoutThreshold !== null && failedAttempts >= lockoutThreshold) {
      updateQuery = `UPDATE userAuthInfo SET failed_login_attempts = ?, last_failed_login_dt = ?, lock_status = 'Lock' WHERE user_id = ?`;
      console.log(`Account locked for userId: ${userId} after ${failedAttempts} failed attempts.`);
    }

    await promisePool.execute(updateQuery, updateParams);
  } catch (error) {
    console.error(`Exception in updating failed login attempts for userId: ${userId}:`, error.message);
  }
};

module.exports = { login };
