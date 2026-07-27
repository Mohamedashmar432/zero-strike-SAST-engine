// ZS-TS-071: cookie explicitly set with httpOnly: false — readable from JavaScript
res.cookie('sid', value, { httpOnly: false });
