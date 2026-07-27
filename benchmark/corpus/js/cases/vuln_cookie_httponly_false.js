// ZS-JS-073: cookie explicitly set with httpOnly: false — readable from JavaScript
res.cookie('sid', value, { httpOnly: false });
