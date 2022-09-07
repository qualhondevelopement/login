const { commonEmitter } = require("../../utils/event-emitter.util");
const { hashSync, genSaltSync, compareSync } = require("bcrypt");
const { sign } = require("jsonwebtoken");
const errorMessages = require("../../utils/errorMessages.utils");

var nodemailer = require("nodemailer");
const { v4: uuidv4 } = require("uuid");

var ejs = require("ejs");
const path = require("path");
var svgCaptcha = require("svg-captcha");

const Path = path.join(__dirname, "../../../../../public");
const config = require("../../../../../config/default.json");
const configs =
  process.env.ENV == "PROD"
    ? config.production
    : process.env.ENV == "DEV"
    ? config.development
    : config.local;

const multer = require("multer");
// const path = require("path");
const fs = require("fs");

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const path = "./public/uploads/assets/users";
    fs.mkdirSync(path, { recursive: true });
    cb(null, path);
  },

  // By default, multer removes file extensions so let's add them back
  filename: function (req, file, cb) {
    let generatedFileName =
      file.fieldname + "-" + Date.now() + path.extname(file.originalname);
    cb(null, generatedFileName);
    // req.uploadPath = "uploads/assets/users/" + generatedFileName;
  },
});

module.exports = {
  /**
   *
   * Function name : "createAdmin"
   * Details : "create new admin user with name and email"
   *
   **/

  createAdmin: async (req, res) => {
    try {
      let upload = multer({
        storage: storage,
        fileFilter(req, file, cb) {
          if (!file.originalname.match(/\.(png|jpg|jpeg)$/)) {
            // upload only png,jpeg and jpg format
            return cb(new Error("Please upload a Image"));
          }
          cb(undefined, true);
        },
      }).single("image");

      upload(req, res, async (err) => {
        if (err) {
          return res.status(400).json({
            message: "Image upload error",
          });
        }

        const body = req.body;
        const salt = genSaltSync(10);

        /**
         *
         * encrypt user password using hashSync
         *
         * */
        body.password = hashSync(body.password, salt);

        // User information by token
        body.agent_added_by = req.decoded.result.id;
        body.uid = uuidv4();
        body.image = req.file ? req.file.path.replace("public", "") : null;
        //console.log("dsadas", typeof body.departmentId);
        try {
          const checkDepartment = await getDepartementByIdCount(
            body.departmentId
          );
          if (checkDepartment[0].count > 0) {
            const checkEmail = await getManagerByEmail(body.email);
            //console.log('ssss', checkEmail.id);
            if (checkEmail.count > 0) {
              if (checkEmail.status == 2) {
                body.id = checkEmail.id;
                await updateAdminStatusById(body);
                body.csrId = checkEmail.id;
                const result = await deleteCSRDept(body);
                const result2 = await insertCSRDepartment(body);
                return res
                  .status(errorMessages.ADMIN_ADDED.code)
                  .json({ message: errorMessages.ADMIN_ADDED.message });
              } else {
                fs.unlink(req.file.path, (err, res) => {});
                return res.status(errorMessages.EMAIL_ALREADY_EXIST.code).json({
                  message: errorMessages.EMAIL_ALREADY_EXIST.message,
                });
              }
            } else {
              const lastInsertId = await createAdmin(body);
              body.csrId = lastInsertId.insertId;
              const result = await insertCSRDepartment(body);
              return res
                .status(errorMessages.ADMIN_ADDED.code)
                .json({ message: errorMessages.ADMIN_ADDED.message });
            }
          } else {
            fs.unlink(req.file.path, (err, res) => {});
            return res
              .status(errorMessages.INVALID_DEPT_DETAILS.code)
              .json({ message: errorMessages.INVALID_DEPT_DETAILS.message });
          }
        } catch (error) {
          fs.unlink(req.file.path, (err, res) => {});
          return res
            .status(errorMessages.INVALID_DEPT_DETAILS.code)
            .json({ message: errorMessages.INVALID_DEPT_DETAILS.message });
        }
      });
    } catch (error) {
      return res
        .status(errorMessages.INVALID_DEPT_DETAILS.code)
        .json({ message: errorMessages.INVALID_DEPT_DETAILS.message });
    }
  },

  /**
   *
   * Function name : "adminList"
   * Details : "list of admins with their details"
   *
   **/
  adminList: async (req, res) => {
    req.search = req.query.search ? req.query.search.trim() : "";
    req.page = req.query.page
      ? req.query.page > 0
        ? parseInt(req.query.page, 10)
        : 1
      : 1;
    req.perPage = req.query.per_page
      ? req.query.per_page > 0
        ? parseInt(req.query.per_page, 10)
        : 10
      : 10;
    // build query
    req.offset = (req.page - 1) * req.perPage;

    try {
      const totalCount = await adminListCount(req);
      const resultList = await adminList(req);
      let resultSet = resultList.map((element) => {
        element.adminStatus = element.status == 1 ? "Active" : "Inactive";
        return element;
      });
      /**
       * Transform array of promises into array of values when fulfilled
       */
      var result = await Promise.all(resultSet);
      return res.status(200).json({
        data: { result, totalCount: totalCount },
      });
    } catch (error) {
      return res.status(errorMessages.SOMETHING_WRONG.code).json({
        message: errorMessages.SOMETHING_WRONG.message,
      });
    }
  },

  adminListForChatTransfer: async (req, res) => {
    try {
      //const totalCount = await adminListCount(req);
      const resultList = await adminListForChatTransfer(req);
      let resultSet = resultList.map((element) => {
        element.adminStatus = element.status == 1 ? "Active" : "Inactive";
        element.agentAddedBy == null ? "N/A" : element.agentAddedBy;
        element.agentPromotedBy == null ? "N/A" : element.agentPromotedBy;
        element.departmentId = element.depts
          ? element.depts.split(",").map((id) => {
              return parseInt(id, 10);
            })
          : [];
        return element;
      });
      /**
       * Transform array of promises into array of values when fulfilled
       */
      var result = await Promise.all(resultSet);
      return res.status(200).json({
        data: result,
      });
    } catch (error) {
      return res.status(errorMessages.SOMETHING_WRONG.code).json({
        message: errorMessages.SOMETHING_WRONG.message,
      });
    }
  },

  deleteAdminById: async (req, res) => {
    const data = parseInt(req.params.id, 10);
    try {
      const totalCount = await adminCountById(data);
      if (totalCount[0].count > 0) {
        const conResult = await conversationAdminCount(totalCount);
        if (!conResult.count) {
          const result = await deleteAdminById(data);
          return res.status(errorMessages.ADMIN_DELETE.code).json({
            message: errorMessages.ADMIN_DELETE.message,
          });
        } else {
          return res.status(errorMessages.ADMIN_ALREADY_USED.code).json({
            message: errorMessages.ADMIN_ALREADY_USED.message,
          });
        }
      } else {
        return res.status(errorMessages.INVALID_USER_DETAILS.code).json({
          message: errorMessages.INVALID_USER_DETAILS.message,
        });
      }
    } catch (error) {
      return res.status(errorMessages.INVALID_USER_DETAILS.code).json({
        message: errorMessages.INVALID_USER_DETAILS.message,
      });
    }
  },

  updateAdminById: async (req, res) => {
    try {
      let upload = multer({
        storage: storage,
        fileFilter(req, file, cb) {
          if (!file.originalname.match(/\.(png|jpg|jpeg)$/)) {
            // upload only png,jpeg and jpg format
            return cb(new Error("Please upload a Image"));
          }
          cb(undefined, true);
        },
      }).single("image");

      upload(req, res, async (err) => {
        if (err) {
          return res.status(400).json({
            message: "Image upload error",
          });
        }
        const body = req.body;
        body.agent_promoted_by = req.decoded.result.id;
        body.agent_added_by = req.decoded.result.id;
        body.csrId = parseInt(req.params.id, 10);
        body.id = parseInt(req.params.id, 10);
        body.image = req.file
          ? req.file.path.replace("public", "")
          : body.old_image;
        const totalCount = await adminCountById(body.id);
        if (totalCount[0].count > 0) {
          const result = await updateAdminById(body);
          if (body.role == 1) {
            const result = await deleteCSRDept(body);
            const result2 = await insertCSRDepartment(body);
          }

          return res.status(errorMessages.ADMIN_UPDATED.code).json({
            message: errorMessages.ADMIN_UPDATED.message,
            response: {
              image: body.image,
            },
          });
        } else {
          return res.status(errorMessages.INVALID_DETAILS.code).json({
            message: errorMessages.INVALID_DETAILS.message,
          });
        }
      });
    } catch (error) {
      return res
        .status(errorMessages.INVALID_DEPT_DETAILS.code)
        .json({ message: errorMessages.INVALID_DEPT_DETAILS.message });
    }
  },

  getAdminById: async (req, res) => {
    const uid = req.params.id;
    try {
      const totalCount = await adminCountById(uid);
      console.log({ totalCount });
      if (totalCount[0].count) {
        const resultList = await getAdminById(uid);
        if (resultList != "") {
          let resultSet = await resultList.map(async (element) => {
            element.agentAddedBy =
              element.agentAddedBy != null ? element.agentAddedBy : "N/A";
            element.agentPromotedBy =
              element.agentPromotedBy != null ? element.agentAddedBy : "N/A";
            element.deptName = await csrDepartmentLisyByID(element.id);
            element.departmentId = element.deptName.map(
              (deptIdss) => deptIdss.deptId
            );
            return element;
          });

          /**
           * Transform array of promises into array of values when fulfilled
           */

          var resultsss = await Promise.all(resultSet);
          let result = resultsss[0];
          return res.status(200).json({ data: { result } });
        } else {
          return res.status(errorMessages.INVALID_DETAILS.code).json({
            message: errorMessages.INVALID_DETAILS.message,
          });
        }
      } else {
        return res.status(errorMessages.INVALID_DETAILS.code).json({
          message: errorMessages.INVALID_DETAILS.message,
        });
      }
    } catch (error) {
      return res.status(errorMessages.SOMETHING_WRONG.code).json({
        message: errorMessages.SOMETHING_WRONG.message,
      });
    }
  },

  /**
   *
   * Function name : "login"
   * Details : "login user with email and password, in response get user details and JWT."
   *
   */

  login: async (req, res) => {
    const body = req.body;
    commonEmitter.emit("User login", body);

    try {
      const results = await getUserByUserEmail(body.email);
      if (results) {
        const result = compareSync(body.password, results.password);

        // if result found with match password
        if (result) {
          results.password = undefined;
          const jsontoken = sign({ result: results }, process.env.JWT_KEY, {
            expiresIn: "16h",
          });

          //check for inactive account
          if (results.status === 1) {
            try {
              //searching the admin,manager and csr in the Session collection
              results.uID;
              results.token = jsontoken;

              const checkSessionCustoms = await checkSessionCustom(results);
              if (checkSessionCustoms[0].count) {
                return res.status(400).json({
                  message: "logout from other devices and login here",
                  isAlreadyLoggedIn: true,
                });
              }

              //insert the admin,manager and csr in the Session collection

              const sessionCustom = await insertSessionCustom(results);

              //Check admin,manager and csr is logout or not
              const ChecklogoutOrNot = await checkAdminUserLogoutOrNot(
                results.id
              );
              if (ChecklogoutOrNot[0].count < 1) {
                // save admin,manager and csr information
                const ChecklogoutOrNot = await insertForLoginHour(results.id);
              }

              /* // save admin,manager and csr information
              const ChecklogoutOrNot = await insertForLoginHour(results.id); */

              results.failed_login_attempts = 0;
              results.remember_token = "";
              results.token_expire = null;
              await updateAdminUserActiveStatus(results);

              return res.status(200).json({
                message: "login successfully",
                token: jsontoken,
                data: {
                  uid: results.uID,
                  name: results.name,
                  email: results.email,
                  role: parseInt(results.role),
                },
              });
            } catch (error) {
              console.error(error);
              return res.status(400).json({
                message: "login hours error",
              });
            }
          } else {
            return res.status(400).json({
              message: "Inactive account. Please contact to admin",
            });
          }
        } else {
          return res
            .status(errorMessages.INVALID_CREDENTIALS.code)
            .json({ message: errorMessages.INVALID_CREDENTIALS.message });
        }
      } else {
        return res
          .status(errorMessages.INVALID_CREDENTIALS.code)
          .json({ message: errorMessages.INVALID_CREDENTIALS.message });
      }
    } catch (error) {
      return res
        .status(errorMessages.INVALID_CREDENTIALS.code)
        .json({ message: errorMessages.INVALID_CREDENTIALS.message });
    }
  },

  refreshCaptcha: (req, res) => {
    var captcha = svgCaptcha.create();
    return res.status(200).json({ message: "", captcha });
  },

  cronLogOut: async (uuid) => {
    try {
      const results = await getAdminDetailsWithUidForCron(uuid);
      if (results) {
        data = {
          id: results.id,
          logout_at: new Date(),
          total_hours: 4,
        };
        try {
          const checkSessionCustoms = await checkSessionCustom({
            uID: uuid,
          });
          const sessionResult = await logoutSessionCustom(uuid);
        } catch (error) {
          return false;
        }
        const result = await insertForLogoutHour(data);
        if (!result) {
          return false;
        }
        return true;
      }
    } catch (error) {
      return false;
    }
  },

  logout: async (req, res) => {
    const body = req.body;
    try {
      const results = await getUserByUserEmail(body.email);
      // commonEmitter.emit('logout admin', results.uID);
      // return res.status(400).json({ message: "logged out" });
      if (results) {
        data = {
          id: results.id,
          logout_at: new Date(),
          total_hours: 4,
        };
        try {
          const checkSessionCustoms = await checkSessionCustom(results);
          const sessionResult = await logoutSessionCustom(results.uID);
        } catch (error) {
          return res.status(400).json({ message: "Invalid email or password" });
        }
        const result = await insertForLogoutHour(data);
        if (!result) {
          return res.status(400).json({ message: "Invalid email or password" });
        }
        if (body.logoutFromOtherDevices) {
          commonEmitter.emit("logout admin", results.uID);
        }
        return res
          .status(200)
          .json({ message: "logout successfully", response: results });
      }
    } catch (error) {
      return res.status(400).json({ message: "Invalid user details" });
    }
  },

  getCatpchaPageLoad: async (req, res) => {
    const body = req.body;
    var getIP = require("ipware")().get_ip;
    var clientIP = getIP(req).clientIp.split(":").pop();
    body.clientIP = clientIP;
    const checkEmailAndIp = await checkTempEmail(body);

    if (checkEmailAndIp[0].login_attempts > 4) {
      var captcha = svgCaptcha.create();
      return res.status(200).json({
        message: "Successsss",
        captcha,
      });
    }
    return res.status(200).json({ message: "Success" });
  },

  forgotPassword: async (req, res) => {
    const body = req.body;
    try {
      const results = await getUserByUserEmail(body.email);

      var getIP = require("ipware")().get_ip;
      var clientIP = getIP(req).clientIp.split(":").pop();
      body.clientIP = clientIP;

      console.log("results", results);

      if (!results) {
        const checkEmailAndIp = await checkTempEmail(body);
        console.log("checkEmailAndIp", checkEmailAndIp);
        console.log(body, "body");
        if (checkEmailAndIp[0].count < 1) {
          try {
            const tempemail = await insertTempEmail(body);
            return res
              .status(400)
              .json({ message: "Email doesn't exist with us" });
          } catch (error) {
            console.log(error);
            return res
              .status(400)
              .json({ message: "Email doesn't exist with us" });
          }
        } else {
          if (checkEmailAndIp[0].id) {
            if (checkEmailAndIp[0].login_attempts <= 4) {
              console.log("less then 4");
              body.id = checkEmailAndIp[0].id;
              body.login_attempts = checkEmailAndIp[0].login_attempts + 1;
              try {
                await updateTempEmail(body);
                return res
                  .status(400)
                  .json({ message: "Email doesn't exist with us" });
              } catch (error) {
                console.log(error);
                return res
                  .status(400)
                  .json({ message: "Email doesn't exist with us" });
              }
            } else {
              var captcha = svgCaptcha.create();
              return res.status(400).json({
                message: "Email doesn't exist with us",
                captcha,
              });
            }
          }
        }
        return res.status(400).json({ message: "Email doesn't exist with us" });
      } else {
        const token = randomString(60);
        body.token = token;
        //curent timestampe plus one hour with date formate
        body.timeStamp = formatDate(dateTimeToTimeStamp(1));

        body.id = results.id;

        var transporter = nodemailer.createTransport({
          service: process.env.EMAIL_HOST,
          auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD,
          },
        });

        ejs.renderFile(
          Path + "/forgot-password.ejs",
          { link: configs.clientBaseUrl + "/auth/verify-token?token=" + token },
          function (err, data) {
            if (err) {
              if (error) {
                return res.status(400).json({ message: "some error occured" });
              }
            } else {
              var mailOptions = {
                from: "gaurav.kakkar@qualhon.com",
                to: body.email,
                subject: "Forgot password",
                html: data,
              };
              transporter.sendMail(mailOptions, function (error, info) {
                if (error) {
                  return res
                    .status(400)
                    .json({ message: "Transport SMTP error" });
                } else {
                  updateTokenWithTime(body, async (err, _) => {
                    if (err) {
                      return res
                        .status(400)
                        .json({ message: "Something went wrong" });
                    }
                    // return res.status(200).json({ message:"Email sent! please check your email for reset password",});
                    // Rate Limit for 5 times

                    if (results.failed_login_attempts < 5) {
                      results.failed_login_attempts =
                        results.failed_login_attempts + 1;
                      await updateAdminUserActiveStatus(results);
                      return res.status(200).json({
                        message:
                          "Email sent! please check your email for reset password",
                      });
                    } else {
                      var captcha = svgCaptcha.create();
                      return res.status(200).json({
                        message:
                          "Email sent! please check your email for reset password",
                        captcha,
                      });
                    }

                    //End rate limit
                  });
                }
              });
            }
          }
        );
      }
    } catch (error) {
      console.log(error);
      return res.status(400).json({ message: "Invalid email" });
    }
  },

  resetPassword: async (req, res) => {
    const body = req.body;
    const id = parseInt(req.body.id, 10);
    const salt = genSaltSync(10);

    if (req.body.token) {
      body.token = req.body.token;
      var d = Date.now();
      body.urlTimeStamp = formatDate(d);
      const checkTokenalue = await tokenExpireOrNot(body);
      if (!checkTokenalue) {
        return res.status(400).json({ message: "Invalid token details" });
      }
    }

    if (body.password != body.cpassword) {
      return res.status(400).json({ message: "Password doesn't match" });
    }
    /**
     *
     * encrypt user password using hashSync
     *
     * */
    body.password = hashSync(req.body.password, salt);
    const totalCount = await mgmntCountById(id);
    if (totalCount[0].count > 0) {
      await resetPassword(body);
      return res.status(200).json({ message: "Password reset successfully" });
    } else {
      return res.status(400).json({ message: "Invalid user details" });
    }
  },
};

function randomString(length) {
  var result = "";
  var chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  for (var i = length; i > 0; --i)
    result += chars[Math.round(Math.random() * (chars.length - 1))];
  return result;
}

function dateTimeToTimeStamp(h) {
  var dt = new Date();
  return dt.setHours(dt.getHours() + h);
}

function formatDate(date) {
  var d = new Date(date);

  (month = "" + (d.getMonth() + 1)),
    (day = "" + d.getDate()),
    (year = d.getFullYear());

  hour = d.getHours();
  minutes = d.getMinutes();
  sec = d.getSeconds();
  if (month.length < 2) month = "0" + month;
  if (day.length < 2) day = "0" + day;

  if (hour.length < 2) hour = "0" + hour;
  if (minutes.length < 2) minutes = "0" + minutes;
  if (sec.length < 2) sec = "0" + sec;

  Dateyearaa = [year, month, day].join("-");
  DateTimes = [hour, minutes, sec].join(":");
  return [Dateyearaa + " " + DateTimes];
}
