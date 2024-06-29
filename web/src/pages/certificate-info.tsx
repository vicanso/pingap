import useConfigStore, { getLocationWeight } from "../states/config";
import { useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";

import Loading from "../components/loading";
import FormEditor from "../components/form-editor";
import { goToCertificateInfo, goToServerInfo } from "../router";
import { FormItem, FormItemCategory } from "../components/form-common";

export default function CertificateInfo() {
  const { t } = useTranslation();

  const [initialized, config, update, remove] = useConfigStore((state) => [
    state.initialized,
    state.data,
    state.update,
    state.remove,
  ]);
  const { name } = useParams();
  if (!initialized) {
    return <Loading />;
  }
  let created = false;
  let certificateName = name;
  if (name == "*") {
    created = true;
    certificateName = "";
  }
  const certificates = config.certificates || {};
  const currentNames = Object.keys(certificates);
  const certificate = certificates[certificateName || ""] || {};

  //  domains?: string;
  // tls_cert?: string;
  // tls_key?: string;
  // certificate_file?: string;
  // acme?: string;
  // remark?: string;
  // "certificate.title": "Certificate for tls",
  // "certificate.description": "The setting of certificate",
  // "certificate.domains": "The domain list fo certificate",
  // "certificate.tlsCert": "Tls Cert Pem",
  // "certificate.tlsKey": "Tls Key Pem",
  // "certificate.certificateFile": "The Https Certificate File",
  // "certificate.acme": "The acme for generate certificate",
  const arr: FormItem[] = [
    {
      id: "tls_cert",
      label: t("certificate.tlsCert"),
      defaultValue: certificate.tls_cert,
      span: 12,
      category: FormItemCategory.TEXTAREA,
    },
    {
      id: "tls_key",
      label: t("certificate.tlsKey"),
      defaultValue: certificate.tls_key,
      span: 12,
      category: FormItemCategory.TEXTAREA,
    },
    {
      id: "tls_chain",
      label: t("certificate.tlsChain"),
      defaultValue: certificate.tls_chain,
      span: 12,
      category: FormItemCategory.TEXTAREA,
    },
    {
      id: "domains",
      label: t("certificate.domains"),
      defaultValue: certificate.domains,
      span: 12,
      category: FormItemCategory.TEXT,
    },
    {
      id: "certificate_file",
      label: t("certificate.certificateFile"),
      defaultValue: certificate.certificate_file,
      span: 12,
      category: FormItemCategory.TEXT,
    },
    {
      id: "acme",
      label: t("certificate.acme"),
      defaultValue: certificate.acme,
      span: 12,
      category: FormItemCategory.CHECKBOX,
      options: [
        {
          label: "Let's Encrypt",
          option: 1,
          value: "lets_encrypt",
        },
        {
          label: "None",
          option: -1,
          value: null,
        },
      ],
    },
  ];

  const onUpsert = async (newName: string, data: Record<string, unknown>) => {
    let certificateName = name || "";
    if (created) {
      certificateName = newName;
    }
    return update("certificate", certificateName, data).then(() => {
      if (created) {
        goToCertificateInfo(certificateName);
      }
    });
  };
  const onRemove = async () => {
    return remove("certificate", name || "").then(() => {
      goToCertificateInfo("*");
    });
  };
  return (
    <FormEditor
      key={name}
      title={t("certificate.title")}
      description={t("certificate.description")}
      items={arr}
      onUpsert={onUpsert}
      onRemove={onRemove}
      created={created}
      currentNames={currentNames}
    />
  );
}
