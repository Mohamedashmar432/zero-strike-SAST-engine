// AngularJS controller trusting a user-supplied HTML string.
angular.module('app').controller('ProfileCtrl', function ($scope, $sce, user) {
  $scope.bio = $sce.trustAsHtml(user.bio);
});
