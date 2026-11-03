declare const $sce: any;

export function show($scope: any, user: { bio: string }): void {
  $scope.bio = $sce.trustAsHtml(user.bio);
}
