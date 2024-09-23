import { MainHeader } from "@/components/header";
import { LoadingPage } from "@/components/loading";
import { MainSidebar } from "@/components/sidebar-nav";
import { useI18n } from "@/i18n";
import useConfigState, { Certificate } from "@/states/config";
import React from "react";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ExForm, ExFormItem } from "@/components/ex-form";
import { z } from "zod";
import {
  ExFormItemCategory,
  newStringOptions,
  newBooleanOptions,
} from "@/constants";

function getCertificateConfig(
  name: string,
  certificates?: Record<string, Certificate>,
) {
  if (!certificates) {
    return {} as Certificate;
  }
  return (certificates[name] || {}) as Certificate;
}

export default function Certificates() {
  const certificateCurrentKey = "certificates.current";
  const certificateI18n = useI18n("certificate");
  const [config, initialized, update, remove] = useConfigState((state) => [
    state.data,
    state.initialized,
    state.update,
    state.remove,
  ]);
  const newCertificate = "*";
  const certificates = Object.keys(config.certificates || {});
  certificates.sort();
  certificates.unshift(newCertificate);
  const [currentCertificate, setCurrentCertificate] = React.useState(
    localStorage.getItem(certificateCurrentKey) || certificates[0],
  );
  if (!initialized) {
    return <LoadingPage />;
  }
  const triggers = certificates.map((item) => {
    let label = item;
    if (label === newCertificate) {
      label = "New";
    }
    return (
      <TabsTrigger key={item} value={item} className="px-4">
        {label}
      </TabsTrigger>
    );
  });

  const handleSelectCertificate = (name: string) => {
    localStorage.setItem(certificateCurrentKey, name);
    setCurrentCertificate(name);
  };

  const tabs = (
    <Tabs value={currentCertificate} onValueChange={handleSelectCertificate}>
      <TabsList className="grid grid-flow-col auto-cols-max">
        {triggers}
      </TabsList>
    </Tabs>
  );

  const certificateConfig = getCertificateConfig(
    currentCertificate,
    config.certificates,
  );

  const items: ExFormItem[] = [
    {
      name: "tls_cert",
      label: certificateI18n("tlsCert"),
      placeholder: certificateI18n("tlsCertPlaceholder"),
      defaultValue: certificateConfig.tls_cert,
      span: 6,
      category: ExFormItemCategory.TEXTAREA,
    },
    {
      name: "tls_key",
      label: certificateI18n("tlsKey"),
      placeholder: certificateI18n("tlsKeyPlaceholder"),
      defaultValue: certificateConfig.tls_key,
      span: 6,
      category: ExFormItemCategory.TEXTAREA,
    },
    {
      name: "tls_chain",
      label: certificateI18n("tlsChain"),
      placeholder: certificateI18n("tlsChainPlaceholder"),
      defaultValue: certificateConfig.tls_chain,
      span: 6,
      category: ExFormItemCategory.TEXTAREA,
    },
    {
      name: "domains",
      label: certificateI18n("domains"),
      placeholder: certificateI18n("domainsPlaceholder"),
      defaultValue: certificateConfig.domains,
      span: 6,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "certificate_file",
      label: certificateI18n("certificateFile"),
      placeholder: certificateI18n("certificateFilePlaceholder"),
      defaultValue: certificateConfig.certificate_file,
      span: 6,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "acme",
      label: certificateI18n("acme"),
      placeholder: "",
      defaultValue: certificateConfig.acme,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newStringOptions(["lets_encrypt"], true),
    },
    {
      name: "is_default",
      label: certificateI18n("isDefault"),
      placeholder: "",
      defaultValue: certificateConfig.is_default,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
  ];

  let defaultShow = 2;
  if (currentCertificate === newCertificate) {
    defaultShow++;
    items.unshift({
      name: "name",
      label: certificateI18n("name"),
      placeholder: certificateI18n("namePlaceholder"),
      defaultValue: "",
      span: 6,
      category: ExFormItemCategory.TEXT,
    });
  }
  const schema = z.object({});

  return (
    <div>
      <MainHeader />
      <div className="flex">
        <MainSidebar className="h-screen flex-none w-[230px]" />
        <div className="grow lg:border-l overflow-auto p-4">
          {tabs}
          <div className="p-2" />
          <ExForm
            key={currentCertificate}
            items={items}
            schema={schema}
            defaultShow={defaultShow}
            onRemove={async () => {
              return remove("certificate", currentCertificate).then(() => {
                handleSelectCertificate(newCertificate);
              });
            }}
            onSave={async (value) => {
              let name = currentCertificate;
              if (name === newCertificate) {
                name = value["name"] as string;
              }
              await update("certificate", name, value);
              handleSelectCertificate(name);
            }}
          />
        </div>
      </div>
    </div>
  );
}
