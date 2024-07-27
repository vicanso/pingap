import * as React from "react";
import { useAsync } from "react-async-hook";
import AppBar from "@mui/material/AppBar";
import Toolbar from "@mui/material/Toolbar";
import Typography from "@mui/material/Typography";
import Box from "@mui/material/Box";
import IconButton from "@mui/material/IconButton";
import SettingsSuggestIcon from "@mui/icons-material/SettingsSuggest";
import SwipeableDrawer from "@mui/material/SwipeableDrawer";
import CardContent from "@mui/material/CardContent";
import Button from "@mui/material/Button";
import Card from "@mui/material/Card";
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import DialogContentText from "@mui/material/DialogContentText";
import DialogTitle from "@mui/material/DialogTitle";
import CodeIcon from "@mui/icons-material/Code";
import { useTranslation } from "react-i18next";
import useBasicStore from "../states/basic";
import request from "../helpers/request";
import { goToTomlPrevew } from "../router";
import Logo from "../../assets/pingap.png";
import Drawer from "@mui/material/Drawer";
import MainNav from "./main-nav";
import MenuOpenIcon from "@mui/icons-material/MenuOpen";

function formatDuraion(ts: number) {
  const seconds = Math.floor(Date.now() / 1000) - ts;
  if (seconds < 60) {
    return `${seconds} seconds ago`;
  }
  if (seconds < 3600) {
    const minutes = Math.floor(seconds / 60);
    if (minutes === 1) {
      return "1 minute ago";
    }
    return `${minutes} minutes ago`;
  }
  if (seconds < 24 * 3600) {
    const hours = Math.floor(seconds / 3600);
    if (hours === 1) {
      return "1 hour ago";
    }
    return `${hours} hours ago`;
  }
  const date = new Date(ts * 1000);
  let month = `${date.getMonth() + 1}`;
  let day = `${date.getDate()}`;
  if (month.length === 1) {
    month = `0${month}`;
  }
  if (day.length === 1) {
    day = `0${day}`;
  }
  return `${month}-${day}`;
}

export default function MainHeader() {
  const { t } = useTranslation();
  const [fetch, basicInfo] = useBasicStore((state) => [
    state.fetch,
    state.data,
  ]);
  const [showSetting, setShowSetting] = React.useState(false);
  const [showRestartDialog, setShowRestartDialog] = React.useState(false);
  const [open, setOpen] = React.useState(false);

  const toggleDrawer = (flag: boolean) => {
    setOpen(flag);
  };

  useAsync(async () => {
    try {
      await fetch();
    } catch (err) {
      console.error(err);
    }
  }, []);

  const confirmRestart = async () => {
    try {
      await request.post("/restart");
      setShowRestartDialog(false);
    } catch (err) {
      console.error(err);
      alert(err);
    }
  };
  const box = (
    <React.Fragment>
      <Box
        display={{
          xs: "block",
          sm: "none",
        }}
      >
        <IconButton
          style={{
            marginRight: "15px",
          }}
          onClick={() => {
            toggleDrawer(true);
          }}
        >
          <MenuOpenIcon />
        </IconButton>
      </Box>
      <IconButton
        aria-label="toml-preview"
        style={{
          marginRight: "15px",
        }}
        onClick={() => {
          goToTomlPrevew();
        }}
      >
        <CodeIcon />
      </IconButton>
      <IconButton
        aria-label="setting"
        onClick={() => {
          setShowSetting(!showSetting);
        }}
      >
        <SettingsSuggestIcon />
      </IconButton>
      <SwipeableDrawer
        anchor="right"
        open={showSetting}
        onClose={() => {
          setShowSetting(false);
        }}
        onOpen={() => {
          setShowSetting(true);
        }}
      >
        <Card sx={{ minWidth: 275, height: "100vh" }}>
          <CardContent>
            <Typography gutterBottom variant="h5" component="div">
              {t("header.title")}
            </Typography>
            <Box pt={2}>
              <Typography gutterBottom variant="body2">
                {t("header.startTime")}
                {formatDuraion(basicInfo.start_time)}
              </Typography>
              <Typography gutterBottom variant="body2">
                {t("header.memory")}
                {basicInfo.memory}
              </Typography>
              <Typography gutterBottom variant="body2">
                {t("header.architecture")}
                {basicInfo.arch}
              </Typography>
              <Typography gutterBottom variant="body2">
                {"Rust: "}
                {basicInfo.rustc_version}
              </Typography>
              <Typography gutterBottom variant="body2">
                {t("header.configHash")}
                {basicInfo.config_hash}
              </Typography>
              <Button
                style={{
                  marginTop: "15px",
                }}
                fullWidth
                variant="outlined"
                onClick={() => {
                  setShowRestartDialog(true);
                }}
              >
                {t("header.restart")}
              </Button>
            </Box>
          </CardContent>
        </Card>
      </SwipeableDrawer>
      <Dialog
        open={showRestartDialog}
        onClose={() => {
          setShowRestartDialog(false);
        }}
        aria-labelledby="alert-dialog-title"
        aria-describedby="alert-dialog-description"
      >
        <DialogTitle id="alert-dialog-title">
          {t("header.confirmTips")}
        </DialogTitle>
        <DialogContent>
          <DialogContentText id="alert-dialog-description">
            {t("header.restartTips")}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              setShowRestartDialog(false);
            }}
          >
            {t("header.cancel")}
          </Button>
          <Button onClick={confirmRestart} autoFocus>
            {t("header.confirm")}
          </Button>
        </DialogActions>
      </Dialog>
    </React.Fragment>
  );
  return (
    <AppBar component="nav">
      <Toolbar>
        <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
          <img
            style={{
              float: "left",
              width: "32px",
              marginRight: "10px",
            }}
            src={Logo}
          />
          Pingap
          <Typography variant="overline" ml={1}>
            {basicInfo.version}
          </Typography>
        </Typography>
        {box}
        <Drawer open={open} onClose={() => toggleDrawer(false)} anchor="top">
          <MainNav fixed={false} navWidth={"100%"} navTop={"0px"} />
        </Drawer>
      </Toolbar>
    </AppBar>
  );
}
