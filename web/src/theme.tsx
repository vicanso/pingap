import { createTheme } from "@mui/material/styles";

const isDarkMode = () =>
  window.matchMedia("(prefers-color-scheme: dark)").matches;

// A custom theme for this app
const theme = createTheme({
  palette: {
    mode: isDarkMode() ? "dark" : "light",
  },
});

export default theme;
