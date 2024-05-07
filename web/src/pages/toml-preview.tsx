import { useAsync } from "react-async-hook";
import * as React from "react";
import Snackbar from "@mui/material/Snackbar";
import Card from "@mui/material/Card";
import CardContent from "@mui/material/CardContent";
import { formatError } from "../helpers/util";
import useConfigStore from "../states/config";

export default function TomlPreview() {
  const [fetch, toml] = useConfigStore((state) => [
    state.fetchToml,
    state.toml,
  ]);
  const [showError, setShowError] = React.useState({
    open: false,
    message: "",
  });
  useAsync(async () => {
    try {
      await fetch();
    } catch (err) {
      setShowError({
        open: true,
        message: formatError(err),
      });
    }
  }, []);

  return (
    <div>
      <Card sx={{ minWidth: 275 }}>
        <CardContent>
          <pre
            style={{
              wordWrap: "break-word",
              wordBreak: "break-all",
              maxWidth: "800px",
            }}
          >
            {toml}
          </pre>
        </CardContent>
      </Card>
      <Snackbar
        open={showError.open}
        autoHideDuration={6000}
        onClose={() => {
          setShowError({
            open: false,
            message: "",
          });
        }}
        message={showError.message}
      />
    </div>
  );
}
