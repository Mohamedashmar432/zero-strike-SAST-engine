// ZS-JS-072: cookie explicitly set with secure: false — sent over plain HTTP
res.cookie('sid', value, { secure: false });
