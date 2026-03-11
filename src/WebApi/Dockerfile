FROM registry.suse.com/bci/dotnet-aspnet:10.0 AS base
USER $APP_UID
WORKDIR /app
EXPOSE 8080
EXPOSE 8081

FROM registry.suse.com/bci/dotnet-sdk:10.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ./Directory.*.props .
COPY ./src ./src
RUN dotnet restore "src/WebApi/WebApi.csproj"
RUN dotnet build "src/WebApi/WebApi.csproj" --no-restore -c "$BUILD_CONFIGURATION"

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
RUN dotnet publish "src/WebApi/WebApi.csproj" --no-build -c "$BUILD_CONFIGURATION" -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
USER $APP_UID
ENV DOTNET_RUNNING_IN_CONTAINER=true \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1
ENTRYPOINT ["dotnet", "Keeptrack.WebApi.dll"]
