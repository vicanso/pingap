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
import Divider from "@mui/material/Divider";
import Card from "@mui/material/Card";

import useBasicStore from "../states/basic";

export default function MainHeader() {
  const [fetch] = useBasicStore((state) => [state.fetch]);
  const [startAt, setStartAt] = React.useState("");
  const [version, setVersion] = React.useState("");
  const [memory, setMemory] = React.useState("");
  const [showSetting, setShowSetting] = React.useState(false);

  useAsync(async () => {
    try {
      const basicInfo = await fetch();
      setStartAt(new Date(basicInfo.start_time * 1000).toLocaleString());
      setVersion(basicInfo.version);
      setMemory(basicInfo.memory);
    } catch (err) {
      console.error(err);
    }
  }, []);
  const box = (
    <React.Fragment>
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
        <Card sx={{ minWidth: 275 }}>
          <CardContent>
            <Typography gutterBottom variant="h5" component="div">
              Informations
            </Typography>
            <Box pt={2}>
              <Typography gutterBottom variant="body2">
                Start Time: {startAt}
              </Typography>
              <Typography gutterBottom variant="body2">
                Memory: {memory}
              </Typography>
            </Box>
          </CardContent>
        </Card>
      </SwipeableDrawer>
    </React.Fragment>
  );
  return (
    <AppBar component="nav">
      <Toolbar>
        <Typography
          variant="h6"
          component="div"
          sx={{ flexGrow: 1, display: { xs: "none", sm: "block" } }}
        >
          Pingap
          <Typography variant="overline" ml={1}>
            {version}
          </Typography>
        </Typography>
        {box}
      </Toolbar>
    </AppBar>
  );
}
