import * as React from "react";
import * as ReactDOM from "react-dom/client";
import { ThemeProvider } from "@emotion/react";
import CssBaseline from "@mui/material/CssBaseline";
import Grid from "@mui/material/Grid";
import theme from "./theme";
import MainNav from "./components/main-nav";
import { RouterProvider } from "react-router-dom";
import MainHeader from "./components/main-header";
import "./i18n";

import router from "./router";

const navWidth = "260px";
const navTop = "58px";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <MainHeader />
      <Grid
        container
        style={{
          marginTop: navTop,
        }}
      >
        <Grid
          item
          sm={"auto"}
          xl={"auto"}
          display={{
            sm: "block",
            xs: "none",
          }}
        >
          <div
            style={{
              width: navWidth,
            }}
          >
            <MainNav fixed={true} navWidth={navWidth} navTop={navTop} />
          </div>
        </Grid>
        <Grid item xs={true}>
          <RouterProvider router={router} />
        </Grid>
      </Grid>
    </ThemeProvider>
  </React.StrictMode>,
);
