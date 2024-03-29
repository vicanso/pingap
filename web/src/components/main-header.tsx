import * as React from "react";
import { useAsync } from "react-async-hook";
import AppBar from "@mui/material/AppBar";
import Toolbar from "@mui/material/Toolbar";
import Typography from "@mui/material/Typography";
import Box from "@mui/material/Box";
import Tooltip from "@mui/material/Tooltip";
import useBasicStore from "../states/basic";

export default function MainHeader() {
  const [fetch] = useBasicStore((state) => [state.fetch]);
  const [startAt, setStartAt] = React.useState("");
  const [version, setVersion] = React.useState("");

  useAsync(async () => {
    try {
      const basicInfo = await fetch();
      setStartAt(new Date(basicInfo.start_time * 1000).toLocaleString());
      setVersion(basicInfo.version);
    } catch (err) {
      console.error(err);
    }
  }, []);
  let box = <></>;
  if (startAt) {
    box = (
      <Box sx={{ display: { xs: "none", sm: "block" } }}>
        <Tooltip title={startAt} placement="bottom">
          <Typography>Start Time</Typography>
        </Tooltip>
      </Box>
    );
  }
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
