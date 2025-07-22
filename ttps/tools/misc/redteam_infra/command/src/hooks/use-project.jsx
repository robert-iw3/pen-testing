"use client";

import { useParams } from "next/navigation";
import React, { createContext, useContext, useState, useEffect } from "react";

const ProjectContext = createContext(null);

export const ProjectProvider = ({ children }) => {
  const params = useParams();
  const projectId = params.projectId;

  return (
    <ProjectContext.Provider
      value={{
        projectId,
      }}
    >
      {children}
    </ProjectContext.Provider>
  );
};

export const useData = () => useContext(ProjectContext);
