@extends('layouts.app')

@section('content')
<h1>Comments</h1>
@foreach ($comments as $comment)
    <div class="body">{!! $comment->body !!}</div>
@endforeach
<p>You searched for: <?= $_GET['q'] ?></p>
@endsection
