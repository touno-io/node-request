module.exports = name => {
  let allow = (process.env.DEBUG || '').indexOf(name) > -1
  return (...msg) => {
    if (allow) {
      console.log(...msg)
    }
  }
}
