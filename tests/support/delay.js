"use strict";

function delay(milliseconds) {
  return new Promise((resolve) => {
    setTimeout(resolve, Math.max(0, milliseconds || 0));
  });
}

module.exports = {
  delay,
};
